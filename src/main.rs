#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod icon;
mod lan;
mod page;
mod platform;
mod theme;

fn main() -> Result<(), eframe::Error> {
    let mut viewport = egui::ViewportBuilder::default()
        .with_inner_size([800.0, 640.0])
        .with_min_inner_size([600.0, 500.0])
        .with_title("密钥快传")
        .with_app_id("secret-drop");
    if let Some(icon) = icon::window_icon() {
        viewport = viewport.with_icon(icon);
    }

    let options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };

    eframe::run_native(
        "SecretDrop",
        options,
        Box::new(|cc| Ok(Box::new(app::SecretDropApp::new(cc)))),
    )
}
