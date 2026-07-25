//! The mouse pointer, which Desktop Duplication hands over *separately* from the screen.
//!
//! Captured frames never contain the cursor. That is deliberate on Windows' part — the pointer is
//! composited by the display hardware — and it is why a naive mirror shows a desktop where nothing
//! ever moves. DXGI gives us the position on every frame and the *shape* only on the frames where
//! it changes, so the shape must be cached.
//!
//! Three shape encodings exist and all three turn up in practice: 32-bit colour, 32-bit "masked"
//! colour, and the 1-bit monochrome format that still backs the classic I-beam. Both masked formats
//! can ask for pixels to be **inverted against whatever is underneath**, which is not something we
//! can honour when the cursor is composited on the far side of a network. Those pixels are
//! approximated as black, and the comments below say so where it happens.

use anyhow::Result;
use windows::Win32::Graphics::Dxgi::*;

pub struct Pointer {
    pub x: i32,
    pub y: i32,
    pub visible: bool,
    /// Set when a new shape arrived and has not yet been sent to the viewer.
    pub fresh_shape: Option<Shape>,
}

pub struct Shape {
    pub w: u32,
    pub h: u32,
    pub hot_x: u32,
    pub hot_y: u32,
    /// RGBA, ready to become a PNG.
    pub rgba: Vec<u8>,
}

impl Default for Pointer {
    fn default() -> Self {
        Self { x: 0, y: 0, visible: false, fresh_shape: None }
    }
}

impl Pointer {
    /// Fold in what a freshly acquired frame says about the pointer.
    pub fn update(
        &mut self,
        dup: &IDXGIOutputDuplication,
        info: &DXGI_OUTDUPL_FRAME_INFO,
    ) -> Result<()> {
        // Position is only meaningful on frames that carry a mouse update; otherwise the fields
        // hold stale values and believing them makes the cursor jump.
        if info.LastMouseUpdateTime != 0 {
            self.x = info.PointerPosition.Position.x;
            self.y = info.PointerPosition.Position.y;
            self.visible = info.PointerPosition.Visible.as_bool();
        }
        if info.PointerShapeBufferSize == 0 {
            return Ok(());
        }

        let mut buf = vec![0u8; info.PointerShapeBufferSize as usize];
        let mut required = 0u32;
        let mut shape_info = DXGI_OUTDUPL_POINTER_SHAPE_INFO::default();
        unsafe {
            dup.GetFramePointerShape(
                buf.len() as u32,
                buf.as_mut_ptr() as *mut _,
                &mut required,
                &mut shape_info,
            )?;
        }
        self.fresh_shape = decode(&buf, &shape_info);
        Ok(())
    }
}

fn decode(buf: &[u8], info: &DXGI_OUTDUPL_POINTER_SHAPE_INFO) -> Option<Shape> {
    let pitch = info.Pitch as usize;
    let (w, h) = (info.Width, info.Height);
    let (hot_x, hot_y) = (info.HotSpot.x as u32, info.HotSpot.y as u32);

    // 1 = monochrome, 2 = colour, 4 = masked colour.
    let rgba = match info.Type {
        1 => {
            // Two stacked 1-bit masks: AND on top, XOR below, so the real height is half.
            let h = h / 2;
            let mut out = vec![0u8; (w * h * 4) as usize];
            for y in 0..h as usize {
                for x in 0..w as usize {
                    let bit = 7 - (x % 8);
                    let and = (buf.get(y * pitch + x / 8)? >> bit) & 1;
                    let xor = (buf.get((y + h as usize) * pitch + x / 8)? >> bit) & 1;
                    let px = &mut out[(y * w as usize + x) * 4..][..4];
                    match (and, xor) {
                        (0, 0) => px.copy_from_slice(&[0, 0, 0, 255]),       // black
                        (0, 1) => px.copy_from_slice(&[255, 255, 255, 255]), // white
                        (1, 0) => px.copy_from_slice(&[0, 0, 0, 0]),         // transparent
                        // "invert what is underneath" — impossible remotely; black reads better
                        // than a hole, and this case is rare outside text carets.
                        _ => px.copy_from_slice(&[0, 0, 0, 255]),
                    }
                }
            }
            return Some(Shape { w, h, hot_x, hot_y, rgba: out });
        }
        2 | 4 => {
            let mut out = vec![0u8; (w * h * 4) as usize];
            for y in 0..h as usize {
                for x in 0..w as usize {
                    let src = &buf.get(y * pitch + x * 4..)?[..4]; // BGRA
                    let (b, g, r, a) = (src[0], src[1], src[2], src[3]);
                    let px = &mut out[(y * w as usize + x) * 4..][..4];
                    if info.Type == 2 {
                        px.copy_from_slice(&[r, g, b, a]);
                    } else {
                        // Masked colour: alpha is a mask, not opacity. 0 means "use this colour",
                        // 0xFF means "XOR with the screen" — again approximated opaquely.
                        match a {
                            0 => px.copy_from_slice(&[r, g, b, 255]),
                            _ => px.copy_from_slice(&[r, g, b, 255]),
                        }
                    }
                }
            }
            out
        }
        _ => return None,
    };
    Some(Shape { w, h, hot_x, hot_y, rgba })
}

/// PNG, because a cursor has hard edges and an alpha channel — exactly what JPEG is worst at.
pub fn to_png(shape: &Shape) -> Result<Vec<u8>> {
    use image::ImageEncoder;
    let mut png = Vec::new();
    image::codecs::png::PngEncoder::new(&mut png).write_image(
        &shape.rgba,
        shape.w,
        shape.h,
        image::ExtendedColorType::Rgba8,
    )?;
    Ok(png)
}
