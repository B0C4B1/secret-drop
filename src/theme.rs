//! 配色、字号与间距常量；同时注册浅色和深色两套视觉，跟随系统主题切换。

use egui::{
    Color32, CornerRadius, FontData, FontDefinitions, FontFamily, FontId, Stroke, TextStyle,
    Visuals,
};

// ---------- 间距与圆角 ----------

pub const GAP_XS: f32 = 4.0;
pub const GAP_SM: f32 = 8.0;
pub const GAP: f32 = 12.0;

pub const RADIUS_LG: u8 = 10;
pub const RADIUS: u8 = 8;
pub const RADIUS_SM: u8 = 6;

// ---------- 字号 ----------

pub const TEXT_TITLE: f32 = 17.0;
pub const TEXT_SECTION: f32 = 14.5;
pub const TEXT_BODY: f32 = 13.0;
pub const TEXT_SMALL: f32 = 11.5;

// ---------- 调色板 ----------

#[derive(Clone, Copy)]
pub struct Palette {
    pub bg: Color32,
    pub surface: Color32,
    pub surface_alt: Color32,
    pub border: Color32,
    pub text: Color32,
    pub text_secondary: Color32,
    pub text_muted: Color32,
    pub accent: Color32,
    pub accent_hover: Color32,
    pub accent_active: Color32,
    pub on_accent: Color32,
    pub accent_text: Color32,
    pub accent_soft: Color32,
    pub hover: Color32,
    pub danger: Color32,
    pub danger_hover: Color32,
    pub on_danger: Color32,
    pub disabled_fill: Color32,
}

/// 浅色：正文对比度均按 WCAG AA 调整（次要文字 ≥ 4.5:1）
pub const LIGHT: Palette = Palette {
    bg: Color32::from_rgb(0xF6, 0xF7, 0xF6),
    surface: Color32::from_rgb(0xFF, 0xFF, 0xFF),
    surface_alt: Color32::from_rgb(0xF9, 0xFA, 0xF9),
    border: Color32::from_rgb(0xDD, 0xE2, 0xDD),
    text: Color32::from_rgb(0x17, 0x18, 0x1A),
    text_secondary: Color32::from_rgb(0x4B, 0x55, 0x63),
    text_muted: Color32::from_rgb(0x6B, 0x72, 0x80),
    accent: Color32::from_rgb(0x8F, 0xD1, 0x4F),
    accent_hover: Color32::from_rgb(0x9C, 0xDD, 0x5F),
    accent_active: Color32::from_rgb(0x7F, 0xC1, 0x3F),
    on_accent: Color32::from_rgb(0x14, 0x1A, 0x0E),
    accent_text: Color32::from_rgb(0x2F, 0x6D, 0x22),
    accent_soft: Color32::from_rgb(0xEA, 0xF6, 0xE3),
    hover: Color32::from_rgb(0xEE, 0xF1, 0xEE),
    danger: Color32::from_rgb(0xB4, 0x23, 0x18),
    danger_hover: Color32::from_rgb(0xC9, 0x3A, 0x2E),
    on_danger: Color32::from_rgb(0xFF, 0xFF, 0xFF),
    disabled_fill: Color32::from_rgb(0xE9, 0xEC, 0xE9),
};

pub const DARK: Palette = Palette {
    bg: Color32::from_rgb(0x11, 0x14, 0x17),
    surface: Color32::from_rgb(0x1A, 0x1E, 0x23),
    surface_alt: Color32::from_rgb(0x20, 0x25, 0x2B),
    border: Color32::from_rgb(0x2E, 0x34, 0x3C),
    text: Color32::from_rgb(0xEC, 0xEF, 0xF2),
    text_secondary: Color32::from_rgb(0xB4, 0xBC, 0xC7),
    text_muted: Color32::from_rgb(0x93, 0x9C, 0xAA),
    accent: Color32::from_rgb(0x8F, 0xD1, 0x4F),
    accent_hover: Color32::from_rgb(0x9C, 0xDD, 0x5F),
    accent_active: Color32::from_rgb(0x7F, 0xC1, 0x3F),
    on_accent: Color32::from_rgb(0x12, 0x18, 0x0C),
    accent_text: Color32::from_rgb(0x9F, 0xDB, 0x72),
    accent_soft: Color32::from_rgb(0x21, 0x30, 0x1B),
    hover: Color32::from_rgb(0x24, 0x2A, 0x31),
    danger: Color32::from_rgb(0xF9, 0x70, 0x66),
    danger_hover: Color32::from_rgb(0xFF, 0x8A, 0x80),
    on_danger: Color32::from_rgb(0x1A, 0x0D, 0x0C),
    disabled_fill: Color32::from_rgb(0x27, 0x2C, 0x33),
};

/// 按当前主题取调色板
pub fn palette(ui: &egui::Ui) -> &'static Palette {
    if ui.visuals().dark_mode {
        &DARK
    } else {
        &LIGHT
    }
}

pub fn palette_ctx(ctx: &egui::Context) -> &'static Palette {
    match ctx.theme() {
        egui::Theme::Dark => &DARK,
        egui::Theme::Light => &LIGHT,
    }
}

/// 应用主题：浅色/深色两套 visuals + 统一字号间距 + 中文字体
pub fn apply(ctx: &egui::Context) {
    ctx.set_theme(egui::ThemePreference::System);
    ctx.set_visuals_of(egui::Theme::Light, visuals(&LIGHT, false));
    ctx.set_visuals_of(egui::Theme::Dark, visuals(&DARK, true));

    ctx.all_styles_mut(|style| {
        style
            .text_styles
            .insert(TextStyle::Heading, FontId::proportional(TEXT_TITLE));
        style
            .text_styles
            .insert(TextStyle::Body, FontId::proportional(TEXT_BODY));
        style
            .text_styles
            .insert(TextStyle::Button, FontId::proportional(TEXT_BODY));
        style
            .text_styles
            .insert(TextStyle::Small, FontId::proportional(TEXT_SMALL));
        style
            .text_styles
            .insert(TextStyle::Monospace, FontId::monospace(TEXT_BODY));

        style.spacing.item_spacing = egui::vec2(GAP_SM, GAP_SM);
        style.spacing.button_padding = egui::vec2(10.0, 5.0);
        style.spacing.interact_size.y = 26.0;
    });

    install_cjk_font(ctx);
}

fn visuals(p: &Palette, dark: bool) -> Visuals {
    let mut v = if dark {
        Visuals::dark()
    } else {
        Visuals::light()
    };

    v.dark_mode = dark;
    v.panel_fill = p.bg;
    v.window_fill = p.surface;
    v.faint_bg_color = p.surface_alt;
    v.extreme_bg_color = p.surface;
    v.text_edit_bg_color = Some(p.surface);
    v.code_bg_color = p.surface_alt;
    v.window_stroke = Stroke::new(1.0, p.border);
    v.window_corner_radius = CornerRadius::same(RADIUS_LG);
    v.menu_corner_radius = CornerRadius::same(RADIUS);
    v.error_fg_color = p.danger;
    v.warn_fg_color = p.danger;

    v.selection.bg_fill = p.accent;
    // 选中态背景是亮绿，文字必须用深色，否则几乎看不见
    v.selection.stroke = Stroke::new(1.0, p.on_accent);
    v.hyperlink_color = p.accent_text;

    // 白底按钮必须有描边，否则和背景几乎无缝
    v.widgets.noninteractive.fg_stroke = Stroke::new(1.0, p.text);
    v.widgets.noninteractive.weak_bg_fill = p.surface;
    v.widgets.noninteractive.bg_stroke = Stroke::new(1.0, p.border);

    v.widgets.inactive.fg_stroke = Stroke::new(1.0, p.text);
    v.widgets.inactive.weak_bg_fill = p.surface;
    v.widgets.inactive.bg_stroke = Stroke::new(1.0, p.border);

    v.widgets.hovered.fg_stroke = Stroke::new(1.0, p.text);
    v.widgets.hovered.weak_bg_fill = p.hover;
    v.widgets.hovered.bg_stroke = Stroke::new(1.0, p.accent);

    v.widgets.active.fg_stroke = Stroke::new(1.0, p.text);
    v.widgets.active.weak_bg_fill = p.accent_soft;
    v.widgets.active.bg_stroke = Stroke::new(1.0, p.accent);

    v.widgets.open.fg_stroke = Stroke::new(1.0, p.text);
    v.widgets.open.weak_bg_fill = p.surface_alt;
    v.widgets.open.bg_stroke = Stroke::new(1.0, p.border);

    v
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
