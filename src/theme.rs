use egui::{Color32, FontData, FontDefinitions, FontFamily, Stroke, Visuals};

pub const BG: Color32 = Color32::from_rgb(0xF6, 0xF7, 0xF6);
pub const SURFACE: Color32 = Color32::from_rgb(0xFF, 0xFF, 0xFF);
pub const BORDER: Color32 = Color32::from_rgb(0xE6, 0xE8, 0xE6);
pub const TEXT: Color32 = Color32::from_rgb(0x17, 0x18, 0x1A);
pub const TEXT_SECONDARY: Color32 = Color32::from_rgb(0x6B, 0x72, 0x80);
pub const TEXT_MUTED: Color32 = Color32::from_rgb(0x9C, 0xA3, 0xAF);
pub const ACCENT: Color32 = Color32::from_rgb(0x8F, 0xD1, 0x4F);
/// 深绿：用于白底上的文字（ACCENT 亮度太高，直接当文字色对比度不足）
pub const ACCENT_TEXT: Color32 = Color32::from_rgb(0x2F, 0x6D, 0x22);
pub const ACCENT_SOFT: Color32 = Color32::from_rgb(0xEA, 0xF6, 0xE3);
pub const HOVER: Color32 = Color32::from_rgb(0xEE, 0xF0, 0xEE);

/// 应用浅色主题并加载中文字体
pub fn apply(ctx: &egui::Context) {
    let mut visuals = Visuals::light();

    visuals.panel_fill = BG;
    visuals.window_fill = SURFACE;
    visuals.faint_bg_color = BG;
    visuals.extreme_bg_color = BG;
    visuals.window_stroke = Stroke::new(1.0, BORDER);

    visuals.selection.bg_fill = ACCENT;
    // 选中态背景是亮绿，文字必须用深色，否则几乎看不见
    visuals.selection.stroke = Stroke::new(1.0, TEXT);
    visuals.hyperlink_color = ACCENT_TEXT;

    visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0, TEXT);
    visuals.widgets.inactive.fg_stroke = Stroke::new(1.0, TEXT);
    visuals.widgets.inactive.weak_bg_fill = SURFACE;
    visuals.widgets.hovered.weak_bg_fill = HOVER;
    visuals.widgets.hovered.bg_stroke = Stroke::new(1.0, ACCENT);
    visuals.widgets.active.weak_bg_fill = ACCENT_SOFT;

    ctx.set_visuals(visuals);
    install_cjk_font(ctx);
}

/// 加载系统中文字体，避免中文显示成方块
fn install_cjk_font(ctx: &egui::Context) {
    let Some(path) = crate::platform::cjk_font_path() else {
        return;
    };
    let Ok(bytes) = std::fs::read(&path) else {
        return;
    };

    // CJK 字形中心偏上，往下微调对齐基线
    let tweak = egui::FontTweak {
        y_offset: 1.0,
        ..Default::default()
    };

    let mut fonts = FontDefinitions::default();
    fonts.font_data.insert(
        "cjk".to_owned(),
        FontData::from_owned(bytes).tweak(tweak).into(),
    );
    fonts
        .families
        .entry(FontFamily::Proportional)
        .or_default()
        .push("cjk".to_owned());
    fonts
        .families
        .entry(FontFamily::Monospace)
        .or_default()
        .push("cjk".to_owned());
    ctx.set_fonts(fonts);
}
