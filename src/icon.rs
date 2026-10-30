//! 应用图标与页头 Logo：编译期嵌入 `assets/icon-256.png`，运行期解码一次。

use std::sync::Arc;

const ICON_PNG: &[u8] = include_bytes!("../assets/icon-256.png");

fn decode() -> Option<image::RgbaImage> {
    image::load_from_memory(ICON_PNG)
        .ok()
        .map(|img| img.to_rgba8())
}

/// 窗口/任务栏图标（macOS 的 Dock 图标来自 .app bundle，不依赖这里）
pub fn window_icon() -> Option<Arc<egui::IconData>> {
    let img = decode()?;
    Some(Arc::new(egui::IconData {
        width: img.width(),
        height: img.height(),
        rgba: img.into_raw(),
    }))
}

/// 页头显示的 Logo 纹理
pub fn logo_texture(ctx: &egui::Context) -> Option<egui::TextureHandle> {
    let img = decode()?;
    let size = [img.width() as usize, img.height() as usize];
    let color = egui::ColorImage::from_rgba_unmultiplied(size, img.as_raw());
    Some(ctx.load_texture("app-logo", color, egui::TextureOptions::LINEAR))
}
