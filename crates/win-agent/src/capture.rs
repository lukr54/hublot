//! Desktop capture via DXGI Desktop Duplication.
//!
//! Measured on real hardware before any of this was designed (`spike-screen`): ~0.76% of a 1080p
//! screen changes in a typical update, ~21 KB once encoded, ~350 µs to encode. Those numbers are
//! why this ships changed rectangles rather than whole frames, and why a plain image codec is
//! enough without reaching for a video encoder.
//!
//! `AcquireNextFrame` blocks until something actually changes, so an idle desktop costs nothing —
//! the same property the console agent gets from `poll()`.

use anyhow::{bail, Context, Result};
use windows::core::Interface;
use windows::Win32::Foundation::{HMODULE, RECT};
use windows::Win32::Graphics::Direct3D::{D3D_DRIVER_TYPE_HARDWARE, D3D_FEATURE_LEVEL_11_0};
use windows::Win32::Graphics::Direct3D11::*;
use windows::Win32::Graphics::Dxgi::Common::*;
use windows::Win32::Graphics::Dxgi::*;

pub struct Capture {
    /// Never read after construction, and not removable: the duplication and the staging texture
    /// are only valid while the device that made them is alive.
    #[allow(dead_code)]
    device: ID3D11Device,
    context: ID3D11DeviceContext,
    dup: IDXGIOutputDuplication,
    staging: ID3D11Texture2D,
    pointer: crate::pointer::Pointer,
    pub width: u32,
    pub height: u32,
    /// Which display this is, so it can be acquired again after Windows takes it away.
    pub output: u32,
}

/// What one capture wake-up produced: possibly a changed region, possibly pointer news, possibly
/// both. Pointer movement alone is the common case and must not force a repaint.
pub enum Update {
    Tile(Tile),
    /// The desktop's size changed — a resolution change, or a different monitor after the
    /// duplication was reacquired. Viewers must resize before the next tile means anything.
    Geometry { w: u16, h: u16 },
    /// Words for the viewer: why the picture has stopped, or that it is back.
    Notice(String),
    Clipboard(String),
    Pointer { x: i16, y: i16, visible: bool },
    Shape { w: u16, h: u16, hot_x: u16, hot_y: u16, png: Vec<u8> },
}

/// A changed region, already encoded.
pub struct Tile {
    pub x: u16,
    pub y: u16,
    pub w: u16,
    pub h: u16,
    pub format: protocol::RasterFormat,
    pub data: Vec<u8>,
}

impl Capture {
    pub fn new(output_index: u32) -> Result<Self> {
        unsafe {
            let mut device = None;
            let mut context = None;
            D3D11CreateDevice(
                None,
                D3D_DRIVER_TYPE_HARDWARE,
                HMODULE::default(),
                D3D11_CREATE_DEVICE_BGRA_SUPPORT,
                Some(&[D3D_FEATURE_LEVEL_11_0]),
                D3D11_SDK_VERSION,
                Some(&mut device),
                None,
                Some(&mut context),
            )
            .context("creating D3D11 device")?;
            let device: ID3D11Device = device.context("no device")?;
            let context: ID3D11DeviceContext = context.context("no context")?;

            let dxgi: IDXGIDevice = device.cast()?;
            let adapter: IDXGIAdapter = dxgi.GetAdapter()?;
            let output: IDXGIOutput = adapter
                .EnumOutputs(output_index)
                .with_context(|| format!("no display output {output_index}"))?;
            let output1: IDXGIOutput1 = output.cast()?;
            let desc = output.GetDesc()?;
            let width = (desc.DesktopCoordinates.right - desc.DesktopCoordinates.left) as u32;
            let height = (desc.DesktopCoordinates.bottom - desc.DesktopCoordinates.top) as u32;

            let dup = output1
                .DuplicateOutput(&device)
                .context("DuplicateOutput — is another capture application holding it?")?;

            let mut staging = None;
            device.CreateTexture2D(
                &D3D11_TEXTURE2D_DESC {
                    Width: width,
                    Height: height,
                    MipLevels: 1,
                    ArraySize: 1,
                    Format: DXGI_FORMAT_B8G8R8A8_UNORM,
                    SampleDesc: DXGI_SAMPLE_DESC { Count: 1, Quality: 0 },
                    Usage: D3D11_USAGE_STAGING,
                    BindFlags: 0,
                    CPUAccessFlags: D3D11_CPU_ACCESS_READ.0 as u32,
                    MiscFlags: 0,
                },
                None,
                Some(&mut staging),
            )?;

            Ok(Self {
                device,
                context,
                dup,
                staging: staging.context("no staging texture")?,
                pointer: Default::default(),
                width,
                height,
                output: output_index,
            })
        }
    }

    /// Grab the whole screen. Used for the first frame a viewer sees, and after any desync.
    pub fn full(&mut self) -> Result<Tile> {
        self.grab(None)
    }

    /// Wait for the next change and return everything it produced.
    ///
    /// The bounding box of all dirty rectangles is used rather than each rectangle separately:
    /// per-tile overhead and round trips cost more than the few extra pixels, at the change sizes
    /// actually measured.
    pub fn next_change(&mut self, timeout_ms: u32) -> Result<Vec<Update>> {
        let mut updates = Vec::new();
        unsafe {
            let mut info = DXGI_OUTDUPL_FRAME_INFO::default();
            let mut resource = None;
            match self.dup.AcquireNextFrame(timeout_ms, &mut info, &mut resource) {
                Ok(()) => {}
                Err(e) if e.code() == DXGI_ERROR_WAIT_TIMEOUT => return Ok(updates),
                Err(e) => bail!("AcquireNextFrame: {e}"),
            }

            let before = (self.pointer.x, self.pointer.y, self.pointer.visible);
            self.pointer.update(&self.dup, &info)?;
            if let Some(shape) = self.pointer.fresh_shape.take() {
                if let Ok(png) = crate::pointer::to_png(&shape) {
                    updates.push(Update::Shape {
                        w: shape.w as u16,
                        h: shape.h as u16,
                        hot_x: shape.hot_x as u16,
                        hot_y: shape.hot_y as u16,
                        png,
                    });
                }
            }
            if (self.pointer.x, self.pointer.y, self.pointer.visible) != before {
                updates.push(Update::Pointer {
                    x: self.pointer.x as i16,
                    y: self.pointer.y as i16,
                    visible: self.pointer.visible,
                });
            }

            let bbox = if info.TotalMetadataBufferSize > 0 {
                let mut buf = vec![0u8; info.TotalMetadataBufferSize as usize];
                let mut needed = 0u32;
                self.dup.GetFrameDirtyRects(
                    buf.len() as u32,
                    buf.as_mut_ptr() as *mut RECT,
                    &mut needed,
                )?;
                let rects = std::slice::from_raw_parts(
                    buf.as_ptr() as *const RECT,
                    needed as usize / std::mem::size_of::<RECT>(),
                );
                rects.iter().fold(None, |acc: Option<RECT>, r| {
                    Some(match acc {
                        None => *r,
                        Some(a) => RECT {
                            left: a.left.min(r.left),
                            top: a.top.min(r.top),
                            right: a.right.max(r.right),
                            bottom: a.bottom.max(r.bottom),
                        },
                    })
                })
            } else {
                None
            };

            // Cursor-only movement leaves `bbox` empty: the pointer news above is the whole update
            // and nothing needs repainting, which is what keeps an idle desktop nearly free.
            if let Some(r) = bbox {
                let tex: ID3D11Texture2D = resource.as_ref().unwrap().cast()?;
                self.context.CopyResource(&self.staging, &tex);
                let tile = self.encode(r)?;
                updates.push(Update::Tile(tile));
            }
            self.dup.ReleaseFrame()?;
            Ok(updates)
        }
    }

    fn grab(&mut self, rect: Option<RECT>) -> Result<Tile> {
        unsafe {
            // A full grab needs a frame in the staging texture; take whatever is current.
            let mut info = DXGI_OUTDUPL_FRAME_INFO::default();
            let mut resource = None;
            if self.dup.AcquireNextFrame(500, &mut info, &mut resource).is_ok() {
                if let Some(res) = resource.as_ref() {
                    let tex: ID3D11Texture2D = res.cast()?;
                    self.context.CopyResource(&self.staging, &tex);
                }
                self.dup.ReleaseFrame()?;
            }
            let r = rect.unwrap_or(RECT {
                left: 0,
                top: 0,
                right: self.width as i32,
                bottom: self.height as i32,
            });
            self.encode(r)
        }
    }

    /// Copy a rectangle out of the staging texture and compress it.
    fn encode(&mut self, r: RECT) -> Result<Tile> {
        unsafe {
            let x0 = r.left.max(0) as u32;
            let y0 = r.top.max(0) as u32;
            let w = (r.right.min(self.width as i32) as u32).saturating_sub(x0).max(1);
            let h = (r.bottom.min(self.height as i32) as u32).saturating_sub(y0).max(1);

            let mut mapped = D3D11_MAPPED_SUBRESOURCE::default();
            self.context.Map(&self.staging, 0, D3D11_MAP_READ, 0, Some(&mut mapped))?;
            let src = mapped.pData as *const u8;
            let mut rgb = Vec::with_capacity((w * h * 3) as usize);
            for y in 0..h {
                let row = src.add(((y0 + y) * mapped.RowPitch) as usize);
                for x in 0..w {
                    let p = row.add(((x0 + x) * 4) as usize);
                    rgb.extend_from_slice(&[*p.add(2), *p.add(1), *p]); // BGRA → RGB
                }
            }
            self.context.Unmap(&self.staging, 0);

            // Small updates are almost always text — a cursor, a line of output, a menu — and
            // JPEG makes text mushy. Large ones are usually window or video content, where lossy
            // compression is both fine and much cheaper. The threshold is a judgement call, not a
            // measurement; revisit it if text ever looks soft.
            let area = w * h;
            let format = if area <= 64_000 {
                protocol::RasterFormat::Png
            } else {
                protocol::RasterFormat::Jpeg
            };

            let mut data = Vec::new();
            match format {
                protocol::RasterFormat::Png => {
                    use image::ImageEncoder;
                    image::codecs::png::PngEncoder::new_with_quality(
                        &mut data,
                        image::codecs::png::CompressionType::Fast,
                        image::codecs::png::FilterType::Adaptive,
                    )
                    .write_image(&rgb, w, h, image::ExtendedColorType::Rgb8)?;
                }
                protocol::RasterFormat::Jpeg => {
                    image::codecs::jpeg::JpegEncoder::new_with_quality(&mut data, 82)
                        .encode(&rgb, w, h, image::ExtendedColorType::Rgb8)?;
                }
            }

            Ok(Tile {
                x: x0 as u16,
                y: y0 as u16,
                w: w as u16,
                h: h as u16,
                format,
                data,
            })
        }
    }
}

// The DXGI objects are only ever touched from the capture thread.
unsafe impl Send for Capture {}
