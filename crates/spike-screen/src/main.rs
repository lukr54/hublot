//! Phase 6 spike — is mirroring a Windows desktop viable for us?
//!
//! The Linux console gave us a 4 KB grid of characters that the kernel had already finished
//! rendering. Windows gives us pixels, and nothing else. Before designing a protocol around that,
//! measure the thing that decides whether this is a weekend or a month:
//!
//!   * how often frames actually arrive, and how long acquiring one costs
//!   * how much of the screen changes in a typical update (the dirty rectangles)
//!   * what those changed regions cost once encoded
//!
//! Everything about the real design — codec, pacing, whether we ship whole frames or tiles —
//! follows from those numbers. Run it, then type in another window while it runs.
//!
//!   cargo run -p spike-screen --release

#[cfg(not(windows))]
fn main() {
    eprintln!("spike-screen is Windows-only");
}

#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    windows_impl::run()
}

#[cfg(windows)]
mod windows_impl {
    use anyhow::{bail, Context, Result};
    use std::time::{Duration, Instant};
    use windows::core::Interface;
    use windows::Win32::Graphics::Direct3D::{D3D_DRIVER_TYPE_HARDWARE, D3D_FEATURE_LEVEL_11_0};
    use windows::Win32::Graphics::Direct3D11::*;
    use windows::Win32::Graphics::Dxgi::Common::*;
    use windows::Win32::Graphics::Dxgi::*;

    const SECONDS: u64 = 12;

    struct Stats {
        frames: u64,
        empty_waits: u64,
        acquire_us: Vec<u128>,
        dirty_pixels: Vec<u64>,
        encoded_bytes: Vec<usize>,
        encode_us: Vec<u128>,
    }

    pub fn run() -> Result<()> {
        unsafe {
            let mut device: Option<ID3D11Device> = None;
            let mut context: Option<ID3D11DeviceContext> = None;
            D3D11CreateDevice(
                None,
                D3D_DRIVER_TYPE_HARDWARE,
                windows::Win32::Foundation::HMODULE::default(),
                D3D11_CREATE_DEVICE_BGRA_SUPPORT,
                Some(&[D3D_FEATURE_LEVEL_11_0]),
                D3D11_SDK_VERSION,
                Some(&mut device),
                None,
                Some(&mut context),
            )
            .context("creating D3D11 device")?;
            let device = device.context("no device")?;
            let context = context.context("no context")?;

            let dxgi: IDXGIDevice = device.cast()?;
            let adapter: IDXGIAdapter = dxgi.GetAdapter()?;
            let output: IDXGIOutput = adapter.EnumOutputs(0).context("no display output 0")?;
            let output1: IDXGIOutput1 = output.cast()?;
            let desc = output.GetDesc()?;
            let (w, h) = (
                (desc.DesktopCoordinates.right - desc.DesktopCoordinates.left) as u32,
                (desc.DesktopCoordinates.bottom - desc.DesktopCoordinates.top) as u32,
            );
            println!("display 0: {w}x{h}");

            let dup: IDXGIOutputDuplication = output1
                .DuplicateOutput(&device)
                .context("DuplicateOutput (is another capture app holding it?)")?;

            // Staging texture: the duplicated frame lives on the GPU; this is how it reaches us.
            let mut staging: Option<ID3D11Texture2D> = None;
            device.CreateTexture2D(
                &D3D11_TEXTURE2D_DESC {
                    Width: w,
                    Height: h,
                    MipLevels: 1,
                    ArraySize: 1,
                    Format: DXGI_FORMAT_B8G8R8A8_UNORM,
                    SampleDesc: DXGI_SAMPLE_DESC {
                        Count: 1,
                        Quality: 0,
                    },
                    Usage: D3D11_USAGE_STAGING,
                    BindFlags: 0,
                    CPUAccessFlags: D3D11_CPU_ACCESS_READ.0 as u32,
                    MiscFlags: 0,
                },
                None,
                Some(&mut staging),
            )?;
            let staging = staging.context("no staging texture")?;

            println!("capturing for {SECONDS}s — go type in another window\n");
            let mut s = Stats {
                frames: 0,
                empty_waits: 0,
                acquire_us: Vec::new(),
                dirty_pixels: Vec::new(),
                encoded_bytes: Vec::new(),
                encode_us: Vec::new(),
            };
            let deadline = Instant::now() + Duration::from_secs(SECONDS);

            while Instant::now() < deadline {
                let mut info = DXGI_OUTDUPL_FRAME_INFO::default();
                let mut resource: Option<IDXGIResource> = None;
                let t0 = Instant::now();
                match dup.AcquireNextFrame(200, &mut info, &mut resource) {
                    Ok(()) => {}
                    Err(e) if e.code() == DXGI_ERROR_WAIT_TIMEOUT => {
                        // Nothing changed on screen. This is the common case at idle and is
                        // exactly why an event-driven design costs nothing when nobody is looking.
                        s.empty_waits += 1;
                        continue;
                    }
                    Err(e) => bail!("AcquireNextFrame: {e}"),
                }
                s.acquire_us.push(t0.elapsed().as_micros());

                // A frame with no accumulated changes is a mouse-move-only update.
                if info.AccumulatedFrames > 0 && info.TotalMetadataBufferSize > 0 {
                    let mut buf = vec![0u8; info.TotalMetadataBufferSize as usize];
                    let mut needed = 0u32;
                    dup.GetFrameDirtyRects(
                        buf.len() as u32,
                        buf.as_mut_ptr() as *mut windows::Win32::Foundation::RECT,
                        &mut needed,
                    )?;
                    let rects = std::slice::from_raw_parts(
                        buf.as_ptr() as *const windows::Win32::Foundation::RECT,
                        needed as usize / std::mem::size_of::<windows::Win32::Foundation::RECT>(),
                    );
                    let pixels: u64 = rects
                        .iter()
                        .map(|r| ((r.right - r.left) as u64) * ((r.bottom - r.top) as u64))
                        .sum();
                    s.dirty_pixels.push(pixels);

                    // Encode the bounding box of the change, which is what we would actually ship.
                    if !rects.is_empty() && s.encoded_bytes.len() < 40 {
                        let tex: ID3D11Texture2D = resource.as_ref().unwrap().cast()?;
                        context.CopyResource(&staging, &tex);
                        let mut mapped = D3D11_MAPPED_SUBRESOURCE::default();
                        context.Map(&staging, 0, D3D11_MAP_READ, 0, Some(&mut mapped))?;

                        let (x0, y0, x1, y1) = rects.iter().fold(
                            (i32::MAX, i32::MAX, 0i32, 0i32),
                            |(a, b, c, d), r| {
                                (a.min(r.left), b.min(r.top), c.max(r.right), d.max(r.bottom))
                            },
                        );
                        let (bw, bh) = ((x1 - x0).max(1) as u32, (y1 - y0).max(1) as u32);
                        let mut rgb = Vec::with_capacity((bw * bh * 3) as usize);
                        let src = mapped.pData as *const u8;
                        for y in 0..bh {
                            let row = src.add(((y0 as u32 + y) * mapped.RowPitch) as usize);
                            for x in 0..bw {
                                let p = row.add(((x0 as u32 + x) * 4) as usize);
                                rgb.extend_from_slice(&[*p.add(2), *p.add(1), *p]);
                                // BGRA → RGB
                            }
                        }
                        context.Unmap(&staging, 0);

                        let t1 = Instant::now();
                        let mut out = Vec::new();
                        image::codecs::jpeg::JpegEncoder::new_with_quality(&mut out, 80).encode(
                            &rgb,
                            bw,
                            bh,
                            image::ExtendedColorType::Rgb8,
                        )?;
                        s.encode_us.push(t1.elapsed().as_micros());
                        s.encoded_bytes.push(out.len());
                    }
                }

                s.frames += 1;
                dup.ReleaseFrame()?;
            }

            report(&s, w, h);
            Ok(())
        }
    }

    fn median(v: &mut [u128]) -> u128 {
        if v.is_empty() {
            return 0;
        }
        v.sort_unstable();
        v[v.len() / 2]
    }

    fn report(s: &Stats, w: u32, h: u32) {
        let mut acq = s.acquire_us.clone();
        let mut enc = s.encode_us.clone();
        let full_raw = (w as u64) * (h as u64) * 4;

        println!("\n──────── results ────────");
        println!("frames delivered : {}", s.frames);
        println!(
            "idle timeouts    : {}  (screen unchanged — costs nothing)",
            s.empty_waits
        );
        println!("acquire median   : {} µs", median(&mut acq));
        if !s.dirty_pixels.is_empty() {
            let total: u64 = s.dirty_pixels.iter().sum();
            let avg = total / s.dirty_pixels.len() as u64;
            let pct = (avg as f64 / (w as f64 * h as f64)) * 100.0;
            println!("dirty px / frame : {avg} ({pct:.2}% of the screen)");
        }
        if !s.encoded_bytes.is_empty() {
            let avg: usize = s.encoded_bytes.iter().sum::<usize>() / s.encoded_bytes.len();
            let max = s.encoded_bytes.iter().max().unwrap();
            println!("encoded / update : {avg} bytes avg, {max} max (JPEG q80, change bbox)");
            println!("encode median    : {} µs", median(&mut enc));
            println!(
                "at 30 fps that is ~{:.1} Mbit/s sustained",
                (avg * 30 * 8) as f64 / 1e6
            );
        }
        println!(
            "full raw frame   : {:.1} MB (for scale)",
            full_raw as f64 / 1e6
        );
        println!(
            "\nCompare against the Linux console leg: ~12 KB per FULL repaint, and nothing at all"
        );
        println!("when idle. That gap is the whole argument for what this leg costs to build.");
    }
}
