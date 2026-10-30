use crate::page::TransferPage;

pub struct SecretDropApp {
    page: TransferPage,
}

impl SecretDropApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        crate::theme::apply(&cc.egui_ctx);
        Self {
            page: TransferPage::default(),
        }
    }
}

impl eframe::App for SecretDropApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ui, |ui| {
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    self.page.ui(ui);
                });
        });
    }
}
