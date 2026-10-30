#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;
mod lan;
mod page;
mod platform;
mod theme;

fn main() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([760.0, 560.0])
            .with_min_inner_size([760.0, 560.0])
            .with_title("密钥快传"),
        ..Default::default()
    };

    eframe::run_native(
        "SecretDrop",
        options,
        Box::new(|cc| Ok(Box::new(app::SecretDropApp::new(cc)))),
    )
}
