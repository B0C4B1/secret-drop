use crate::page::TransferPage;

pub struct SecretDropApp {
    page: TransferPage,
}

impl SecretDropApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        crate::theme::apply(&cc.egui_ctx);
        Self {
            page: TransferPage::new(&cc.egui_ctx),
        }
    }
}

impl eframe::App for SecretDropApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ui, |ui| {
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    // 大窗口下限制内容宽度并居中，避免控件被无限拉伸
                    let avail = ui.available_width();
                    let width = (avail - 24.0).clamp(320.0, 820.0);
                    let side = ((avail - width) / 2.0).max(0.0);
                    ui.horizontal_top(|ui| {
                        ui.add_space(side);
                        ui.vertical(|ui| {
                            ui.set_width(width);
                            self.page.ui(ui);
                        });
                    });
                });
        });
    }
}
