//! 密钥快传界面：发送方生成一次性密钥，接收方输入密钥接收文件。

use std::fs::OpenOptions;
use std::io::Write;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use egui::{Align, Key, Layout, Margin, RichText, Stroke};

use crate::lan::{Collab, ShareItem};
use crate::theme::{self, Palette};

/// 接收历史最多保留的条数，超出后丢弃最旧的记录
const HISTORY_LIMIT: usize = 20;

pub struct TransferPage {
    port: String,
    /// UDP 发现端口，两端必须一致；7778 被占用时可改
    discovery_port: String,
    collab: Option<Arc<Collab>>,
    download_dir: Option<PathBuf>,

    key_input: String,
    /// 广播搜不到时的兜底：手动指定发送方 IP
    peer_ip: String,
    /// 无系统文件对话框时的兜底：手动输入文件路径
    file_path_input: String,
    received: Vec<String>,

    share_status: Option<Status>,
    recv_status: Option<Status>,

    recv_name: Option<String>,
    progress_written: u64,
    progress_total: u64,
    recv_started: Option<Instant>,
    /// 上一次测速采样点
    sample: Option<(Instant, u64)>,
    speed: f64,

    receiving: bool,
    rx: Option<mpsc::Receiver<RecvMsg>>,
    cancel: Option<Arc<AtomicBool>>,

    /// 后台文件对话框的结果通道
    dialog: Option<mpsc::Receiver<DialogResult>>,
    confirm: Option<Confirm>,
    /// 本帧指针是否停在下载目录拖放区
    drop_target_hover: bool,
    logo: Option<egui::TextureHandle>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum StatusKind {
    Info,
    Ok,
    Error,
}

struct Status {
    kind: StatusKind,
    text: String,
}

impl Status {
    fn info(text: impl Into<String>) -> Self {
        Self {
            kind: StatusKind::Info,
            text: text.into(),
        }
    }

    fn ok(text: impl Into<String>) -> Self {
        Self {
            kind: StatusKind::Ok,
            text: text.into(),
        }
    }

    fn error(text: impl Into<String>) -> Self {
        Self {
            kind: StatusKind::Error,
            text: text.into(),
        }
    }
}

enum RecvMsg {
    /// 发现阶段完成，已知对方文件名与大小
    Started {
        name: String,
        total: u64,
    },
    Progress(u64, u64),
    Done(PathBuf),
    Err(String),
}

#[derive(Clone)]
enum DialogResult {
    Files(Vec<PathBuf>),
    Folder(Option<PathBuf>),
    DownloadDir(Option<PathBuf>),
}

#[derive(Clone, Copy)]
enum DialogKind {
    Files,
    Folder,
    DownloadDir,
}

#[derive(Clone)]
enum ConfirmAction {
    Remove(String),
    ClearHistory,
}

struct Confirm {
    title: String,
    body: String,
    action: ConfirmAction,
}

impl Default for TransferPage {
    fn default() -> Self {
        Self {
            port: "8765".to_string(),
            discovery_port: crate::lan::DEFAULT_DISCOVERY_PORT.to_string(),
            collab: None,
            download_dir: None,
            key_input: String::new(),
            peer_ip: String::new(),
            file_path_input: String::new(),
            received: load_history(),
            share_status: None,
            recv_status: None,
            recv_name: None,
            progress_written: 0,
            progress_total: 0,
            recv_started: None,
            sample: None,
            speed: 0.0,
            receiving: false,
            rx: None,
            cancel: None,
            dialog: None,
            confirm: None,
            drop_target_hover: false,
            logo: None,
        }
    }
}

impl TransferPage {
    pub fn new(ctx: &egui::Context) -> Self {
        Self {
            logo: crate::icon::logo_texture(ctx),
            ..Default::default()
        }
    }

    pub fn ui(&mut self, ui: &mut egui::Ui) {
        self.poll(ui.ctx());
        self.auto_stop();

        let pal = theme::palette(ui);
        self.header(ui, pal);
        ui.add_space(theme::GAP);
        self.share_ui(ui, pal);
        ui.add_space(theme::GAP);
        self.receive_ui(ui, pal);
        ui.add_space(theme::GAP);
        self.settings_ui(ui, pal);
        ui.add_space(theme::GAP_SM);
        ui.label(
            RichText::new("文件只在局域网内点对点传输，密钥不经过任何服务器。")
                .size(theme::TEXT_SMALL)
                .color(pal.text_muted),
        );

        self.handle_drops(ui);
        self.confirm_ui(ui.ctx());
    }
    // ---------- 状态轮询 ----------

    fn poll(&mut self, ctx: &egui::Context) {
        if self.receiving
            && ctx.input(|i| i.key_pressed(Key::Escape))
            && let Some(c) = &self.cancel
        {
            c.store(true, Ordering::Relaxed);
        }

        let mut msgs = Vec::new();
        let mut disconnected = false;
        if let Some(rx) = &self.rx {
            loop {
                match rx.try_recv() {
                    Ok(m) => msgs.push(m),
                    Err(mpsc::TryRecvError::Empty) => break,
                    Err(mpsc::TryRecvError::Disconnected) => {
                        disconnected = true;
                        break;
                    }
                }
            }
        }

        for msg in msgs {
            match msg {
                RecvMsg::Started { name, total } => {
                    self.recv_name = Some(name);
                    self.progress_total = total;
                    self.recv_status = Some(Status::info("已找到发送方，正在建立连接…"));
                }
                RecvMsg::Progress(written, total) => {
                    self.progress_written = written;
                    self.progress_total = total;
                    self.track_speed(written);
                }
                RecvMsg::Done(path) => {
                    let shown = path.display().to_string();
                    self.received.push(shown.clone());
                    if self.received.len() > HISTORY_LIMIT {
                        let extra = self.received.len() - HISTORY_LIMIT;
                        self.received.drain(..extra);
                    }
                    append_history(&shown);
                    self.recv_status = Some(Status::ok(format!("接收完成，已保存到 {shown}")));
                    self.key_input.clear();
                    self.finish_receive();
                }
                RecvMsg::Err(e) => {
                    self.recv_status = Some(if e == "已取消" {
                        Status::info("已取消接收")
                    } else {
                        Status::error(format!("接收失败：{e}"))
                    });
                    self.finish_receive();
                }
            }
        }

        if disconnected && self.receiving {
            self.recv_status = Some(Status::error("接收失败：连接意外中断"));
            self.finish_receive();
        }

        self.poll_dialog();

        if self.receiving {
            ctx.request_repaint_after(Duration::from_millis(100));
        }
    }

    fn finish_receive(&mut self) {
        self.receiving = false;
        self.rx = None;
        self.cancel = None;
        self.sample = None;
    }

    /// 用两次采样的差值估算速度，做指数平滑避免数字跳动
    fn track_speed(&mut self, written: u64) {
        let now = Instant::now();
        match self.sample {
            Some((t, w)) => {
                let dt = now.duration_since(t).as_secs_f64();
                if dt >= 0.3 {
                    let inst = written.saturating_sub(w) as f64 / dt;
                    self.speed = if self.speed <= 0.0 {
                        inst
                    } else {
                        self.speed * 0.6 + inst * 0.4
                    };
                    self.sample = Some((now, written));
                }
            }
            None => self.sample = Some((now, written)),
        }
    }

    fn poll_dialog(&mut self) {
        let mut result = None;
        if let Some(rx) = &self.dialog {
            match rx.try_recv() {
                Ok(r) => result = Some(r),
                Err(mpsc::TryRecvError::Empty) => {}
                Err(mpsc::TryRecvError::Disconnected) => result = Some(DialogResult::Folder(None)),
            }
        }
        let Some(result) = result else { return };
        self.dialog = None;
        match result {
            DialogResult::Files(files) if !files.is_empty() => {
                self.share_paths(files);
            }
            DialogResult::Files(_) => {
                self.share_status = Some(Status::info("未选择文件"));
            }
            DialogResult::Folder(Some(dir)) => {
                self.share_paths(vec![dir]);
            }
            DialogResult::Folder(None) => {
                self.share_status = Some(Status::info("未选择文件夹"));
            }
            DialogResult::DownloadDir(dir) => {
                if dir.is_some() {
                    self.download_dir = dir;
                    self.recv_status = Some(Status::info("已更新保存目录"));
                }
            }
        }
    }

    // ---------- 协作服务 ----------

    fn parse_port(&self) -> Result<u16, String> {
        match self.port.trim().parse() {
            Ok(p) if p > 0 => Ok(p),
            _ => Err("端口无效".to_string()),
        }
    }

    fn parse_discovery_port(&self) -> Result<u16, String> {
        match self.discovery_port.trim().parse() {
            Ok(p) if p > 0 => Ok(p),
            _ => Err("发现端口无效".to_string()),
        }
    }

    /// 按需启动：首次使用时创建，未运行则启动端口
    fn ensure_started(&mut self) -> Result<Arc<Collab>, String> {
        let port = self.parse_port()?;
        let discovery_port = self.parse_discovery_port()?;
        if let Some(c) = &self.collab {
            if c.port() == port && c.discovery_port() == discovery_port {
                if !c.is_running() {
                    c.clone().start()?;
                }
                return Ok(c.clone());
            }
            // 端口变化：还有待接收的分享时不允许重建，否则密钥会被静默作废
            if c.has_pending() {
                return Err("修改端口会作废当前密钥，请先移除已分享的文件".to_string());
            }
            if c.is_running() {
                return Err("端口正在使用中，请等待当前传输结束后再修改".to_string());
            }
        }
        let c = Arc::new(Collab::new(port, discovery_port));
        self.collab = Some(c.clone());
        c.start()?;
        Ok(c)
    }

    /// 没有待接收文件、也没有进行中的接收时，自动关闭端口
    fn auto_stop(&mut self) {
        if self.receiving {
            return;
        }
        if let Some(c) = &self.collab {
            c.maybe_auto_stop();
        }
    }

    // ---------- 布局骨架 ----------

    fn header(&mut self, ui: &mut egui::Ui, pal: &Palette) {
        if self.logo.is_none() {
            self.logo = crate::icon::logo_texture(ui.ctx());
        }
        ui.horizontal(|ui| {
            if let Some(tex) = &self.logo {
                ui.add(
                    egui::Image::new((tex.id(), egui::vec2(34.0, 34.0)))
                        .corner_radius(theme::RADIUS_SM),
                );
                ui.add_space(theme::GAP_XS);
            }
            ui.vertical(|ui| {
                ui.label(
                    RichText::new("密钥快传")
                        .size(theme::TEXT_TITLE)
                        .strong()
                        .color(pal.text),
                );
                ui.label(
                    RichText::new("一次性密钥 · 局域网直传 · 不经过服务器")
                        .size(theme::TEXT_SMALL)
                        .color(pal.text_muted),
                );
            });
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.label(
                    RichText::new(concat!("v", env!("CARGO_PKG_VERSION")))
                        .size(theme::TEXT_SMALL)
                        .color(pal.text_muted),
                );
            });
        });
    }

    /// 卡片容器：统一白底 + 细描边 + 圆角
    fn card<R>(ui: &mut egui::Ui, pal: &Palette, add: impl FnOnce(&mut egui::Ui) -> R) -> R {
        let width = ui.available_width();
        egui::Frame::new()
            .fill(pal.surface)
            .stroke(Stroke::new(1.0, pal.border))
            .corner_radius(theme::RADIUS)
            .inner_margin(Margin::symmetric(14, 12))
            .show(ui, |ui| {
                ui.set_width((width - 28.0).max(200.0));
                add(ui)
            })
            .inner
    }

    fn handle_drops(&mut self, ui: &egui::Ui) {
        let dropped = ui.ctx().input(|i| i.raw.dropped_files.clone());
        if dropped.is_empty() {
            return;
        }
        let paths: Vec<PathBuf> = dropped.iter().map(|f| f.path().to_path_buf()).collect();
        if paths.is_empty() {
            return;
        }
        if self.drop_target_hover {
            let first = &paths[0];
            let dir = if first.is_dir() {
                first.clone()
            } else {
                first
                    .parent()
                    .map(std::path::Path::to_path_buf)
                    .unwrap_or_else(|| first.clone())
            };
            self.download_dir = Some(dir);
            self.recv_status = Some(Status::info("已把拖入位置设为保存目录"));
        } else if !self.receiving {
            self.share_paths(paths);
        }
    }
    // ---------- 发送区 ----------

    fn share_ui(&mut self, ui: &mut egui::Ui, pal: &Palette) {
        Self::card(ui, pal, |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new("发送文件")
                        .size(theme::TEXT_SECTION)
                        .strong()
                        .color(pal.text),
                );
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.label(
                        RichText::new("对方在同一局域网即可")
                            .size(theme::TEXT_SMALL)
                            .color(pal.text_muted),
                    );
                });
            });
            ui.add_space(theme::GAP_SM);

            let busy = self.receiving || self.dialog.is_some();
            ui.horizontal(|ui| {
                if primary_button(ui, pal, "📄 选择文件", !busy).clicked() {
                    self.open_dialog(DialogKind::Files);
                }
                if secondary_button(ui, pal, "📁 发送文件夹（打包）", !busy).clicked() {
                    self.open_dialog(DialogKind::Folder);
                }
                if self.dialog.is_some() {
                    ui.add(egui::Spinner::new().size(14.0).color(pal.accent));
                }
            });

            // 精简 Linux 桌面可能没有文件对话框后端，留一条手动输入的退路
            egui::CollapsingHeader::new(
                RichText::new("手动输入文件路径")
                    .size(theme::TEXT_SMALL)
                    .color(pal.text_muted),
            )
            .id_salt("manual_file_path")
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.file_path_input)
                            .hint_text("没有弹出选择框时可在这里输入完整路径")
                            .desired_width(260.0),
                    );
                    if secondary_button(ui, pal, "分享", !busy).clicked() {
                        self.share_path();
                    }
                });
            });

            if let Some(s) = &self.share_status {
                ui.add_space(theme::GAP_XS);
                status_row(ui, pal, s);
            }

            let items: Vec<ShareItem> = self
                .collab
                .as_ref()
                .map(|c| c.list_shares())
                .unwrap_or_default();

            if items.is_empty() {
                ui.add_space(theme::GAP);
                ui.vertical_centered(|ui| {
                    ui.label(RichText::new("📤").size(20.0).color(pal.text_muted));
                    ui.label(
                        RichText::new("还没有待发送的文件")
                            .size(theme::TEXT_BODY)
                            .color(pal.text_secondary),
                    );
                    ui.label(
                        RichText::new("选好文件后会生成一次性密钥，把它告诉对方即可")
                            .size(theme::TEXT_SMALL)
                            .color(pal.text_muted),
                    );
                });
                ui.add_space(theme::GAP_SM);
                return;
            }

            ui.add_space(theme::GAP_SM);
            ui.horizontal_wrapped(|ui| {
                if let Some(ip) = Collab::local_ipv4() {
                    ui.label(
                        RichText::new(format!("本机地址 {ip}"))
                            .size(theme::TEXT_SMALL)
                            .color(pal.text_muted),
                    );
                }
                if let Some(ip) = Collab::local_ipv6() {
                    ui.label(
                        RichText::new(format!("IPv6 {ip}"))
                            .size(theme::TEXT_SMALL)
                            .color(pal.text_muted),
                    );
                }
            });

            let mut copy: Option<String> = None;
            let mut regen: Option<String> = None;
            let mut ask_remove: Option<String> = None;
            let row_w = ui.available_width();

            for it in &items {
                let used = it.used;
                let accent = if used {
                    pal.text_muted
                } else {
                    pal.accent_text
                };
                let fill = if used {
                    pal.surface_alt
                } else {
                    pal.accent_soft
                };
                ui.add_space(theme::GAP_XS);
                egui::Frame::new()
                    .fill(fill)
                    .corner_radius(theme::RADIUS_SM)
                    .inner_margin(Margin::symmetric(10, 8))
                    .show(ui, |ui| {
                        ui.set_width((row_w - 20.0).max(120.0));
                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new(format_key(&it.key))
                                    .monospace()
                                    .size(15.0)
                                    .strong()
                                    .color(accent),
                            );
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                let (txt, color) = if used {
                                    ("已接收".to_string(), pal.text_muted)
                                } else {
                                    (
                                        format!("待接收 · 剩 {}", format_secs(it.remaining_secs)),
                                        accent,
                                    )
                                };
                                ui.label(RichText::new(txt).size(theme::TEXT_SMALL).color(color));
                            });
                        });
                        ui.add_space(2.0);
                        ui.horizontal(|ui| {
                            let actions_w = if used { 96.0 } else { 268.0 };
                            let name_w = (ui.available_width() - actions_w).max(80.0);
                            ui.add_sized(
                                [name_w, 22.0],
                                egui::Label::new(
                                    RichText::new(format!(
                                        "{} · {}",
                                        it.file_name,
                                        format_size(it.file_size)
                                    ))
                                    .size(theme::TEXT_BODY)
                                    .color(pal.text),
                                )
                                .truncate(),
                            )
                            .on_hover_text(&it.file_name);

                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                if small_button(ui, "🗑 移除", pal.danger).clicked() {
                                    ask_remove = Some(it.key.clone());
                                }
                                if !used {
                                    if small_button(ui, "🔄 重新生成", pal.accent_text).clicked()
                                    {
                                        regen = Some(it.key.clone());
                                    }
                                    if small_button(ui, "📋 复制密钥", pal.text_secondary).clicked()
                                    {
                                        copy = Some(it.key.clone());
                                    }
                                }
                            });
                        });
                    });
            }

            if let Some(k) = copy {
                ui.ctx().copy_text(k.clone());
                self.share_status = Some(Status::ok(format!("已复制密钥：{}", format_key(&k))));
            }
            if let Some(k) = regen {
                self.regenerate(&k);
            }
            if let Some(k) = ask_remove {
                self.confirm = Some(Confirm {
                    title: "移除这个分享？".to_string(),
                    body: "移除后密钥立即失效，对方将无法再接收这个文件。".to_string(),
                    action: ConfirmAction::Remove(k),
                });
            }
        });
    }

    fn open_dialog(&mut self, kind: DialogKind) {
        if self.dialog.is_some() {
            return;
        }
        let (tx, rx) = mpsc::channel();
        self.dialog = Some(rx);
        // 系统文件对话框会阻塞当前线程，必须放到后台
        std::thread::spawn(move || {
            let result = match kind {
                DialogKind::Files => {
                    DialogResult::Files(rfd::FileDialog::new().pick_files().unwrap_or_default())
                }
                DialogKind::Folder => DialogResult::Folder(rfd::FileDialog::new().pick_folder()),
                DialogKind::DownloadDir => {
                    DialogResult::DownloadDir(rfd::FileDialog::new().pick_folder())
                }
            };
            let _ = tx.send(result);
        });
    }

    fn share_path(&mut self) {
        let raw = self.file_path_input.trim();
        if raw.is_empty() {
            self.share_status = Some(Status::error("请输入文件路径"));
            return;
        }
        let file = PathBuf::from(raw);
        if !file.is_file() {
            self.share_status = Some(Status::error(format!(
                "路径不存在或不是文件：{}",
                file.display()
            )));
            return;
        }
        self.file_path_input.clear();
        self.share_paths(vec![file]);
    }

    fn share_paths(&mut self, paths: Vec<PathBuf>) {
        let collab = match self.ensure_started() {
            Ok(c) => c,
            Err(e) => {
                self.share_status = Some(Status::error(e));
                return;
            }
        };
        match collab.share_paths(paths) {
            Ok(key) => {
                self.share_status = Some(Status::ok(format!(
                    "已生成密钥 {}，把它告诉对方",
                    format_key(&key)
                )));
            }
            Err(e) => self.share_status = Some(Status::error(e)),
        }
    }

    fn regenerate(&mut self, key: &str) {
        let collab = match self.ensure_started() {
            Ok(c) => c,
            Err(e) => {
                self.share_status = Some(Status::error(e));
                return;
            }
        };
        match collab.regenerate(key) {
            Ok(new) => {
                self.share_status =
                    Some(Status::ok(format!("已重新生成密钥 {}", format_key(&new))));
            }
            Err(e) => self.share_status = Some(Status::error(e)),
        }
    }

    fn remove(&mut self, key: &str) {
        if let Some(c) = &self.collab {
            c.remove_share(key);
        }
        self.share_status = Some(Status::info("已移除该分享"));
    }
    // ---------- 接收区 ----------

    fn receive_ui(&mut self, ui: &mut egui::Ui, pal: &Palette) {
        Self::card(ui, pal, |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new("接收文件")
                        .size(theme::TEXT_SECTION)
                        .strong()
                        .color(pal.text),
                );
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.label(
                        RichText::new("输入对方给的密钥")
                            .size(theme::TEXT_SMALL)
                            .color(pal.text_muted),
                    );
                });
            });
            ui.add_space(theme::GAP_SM);

            let mut submit = false;
            ui.horizontal(|ui| {
                let resp = ui.add(
                    egui::TextEdit::singleline(&mut self.key_input)
                        .hint_text("ABCD-2345")
                        .font(egui::TextStyle::Monospace)
                        .char_limit(9)
                        .desired_width(150.0),
                );
                // 统一成大写，方便和对方核对
                let upper = self.key_input.to_ascii_uppercase();
                if upper != self.key_input {
                    self.key_input = upper;
                }
                let enter = resp.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter));
                let clicked = primary_button(ui, pal, "⬇ 接收", !self.receiving).clicked();
                submit = enter || clicked;
            });

            ui.add_space(theme::GAP_XS);
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new("保存到")
                        .size(theme::TEXT_SMALL)
                        .color(pal.text_muted),
                );
                self.dir_picker(ui, pal);
            });

            if let Some(s) = &self.recv_status {
                ui.add_space(theme::GAP_XS);
                status_row(ui, pal, s);
            }

            if self.receiving {
                ui.add_space(theme::GAP_SM);
                let name = self
                    .recv_name
                    .clone()
                    .unwrap_or_else(|| "正在查找持有该密钥的设备…".to_string());
                ui.horizontal(|ui| {
                    ui.add(egui::Spinner::new().size(15.0).color(pal.accent));
                    ui.add(
                        egui::Label::new(
                            RichText::new(name).size(theme::TEXT_BODY).color(pal.text),
                        )
                        .truncate(),
                    );
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if small_button(ui, "❌ 取消", pal.danger).clicked()
                            && let Some(c) = &self.cancel
                        {
                            c.store(true, Ordering::Relaxed);
                        }
                    });
                });
                if self.progress_total > 0 {
                    let frac =
                        (self.progress_written as f32 / self.progress_total as f32).clamp(0.0, 1.0);
                    ui.add_space(theme::GAP_XS);
                    ui.add(
                        egui::ProgressBar::new(frac)
                            .fill(pal.accent)
                            .desired_height(8.0)
                            .corner_radius(theme::RADIUS_SM),
                    );
                    ui.add_space(2.0);
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new(format!(
                                "{:.0}% · {} / {}",
                                frac * 100.0,
                                format_size(self.progress_written),
                                format_size(self.progress_total)
                            ))
                            .size(theme::TEXT_SMALL)
                            .color(pal.text_secondary),
                        );
                        let eta = self.eta();
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            ui.label(
                                RichText::new(format!("{} · 剩余 {eta}", format_speed(self.speed)))
                                    .size(theme::TEXT_SMALL)
                                    .color(pal.text_muted),
                            );
                        });
                    });
                }
            }

            // 广播在多网卡/VPN/防火墙环境下可能搜不到对端，直连可绕过发现阶段
            egui::CollapsingHeader::new(
                RichText::new("广播搜不到？直连发送方 IP")
                    .size(theme::TEXT_SMALL)
                    .color(pal.text_muted),
            )
            .id_salt("manual_peer_ip")
            .show(ui, |ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut self.peer_ip)
                        .hint_text("留空自动搜索，例如 192.168.1.23 或 fe80::1")
                        .desired_width(260.0),
                );
            });

            if !self.received.is_empty() {
                ui.add_space(theme::GAP);
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("最近接收")
                            .size(theme::TEXT_SMALL)
                            .color(pal.text_secondary),
                    );
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if small_button(ui, "🗑 清除历史", pal.text_muted).clicked() {
                            self.confirm = Some(Confirm {
                                title: "清除接收历史？".to_string(),
                                body: "只删除本机的记录，不会删除已经下载的文件。".to_string(),
                                action: ConfirmAction::ClearHistory,
                            });
                        }
                    });
                });

                let mut open_file: Option<PathBuf> = None;
                let mut open_dir: Option<PathBuf> = None;
                let row_w = ui.available_width();
                for entry in &self.received {
                    ui.horizontal(|ui| {
                        let name_w = (row_w - 132.0).max(80.0);
                        ui.add_sized(
                            [name_w, 20.0],
                            egui::Label::new(
                                RichText::new(entry).size(theme::TEXT_SMALL).color(pal.text),
                            )
                            .truncate(),
                        )
                        .on_hover_text(entry);
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if small_button(ui, "文件夹", pal.text_secondary).clicked() {
                                let p = PathBuf::from(entry);
                                open_dir = p.parent().map(std::path::Path::to_path_buf);
                            }
                            if small_button(ui, "打开", pal.text_secondary).clicked() {
                                open_file = Some(PathBuf::from(entry));
                            }
                        });
                    });
                }
                if let Some(p) = open_file {
                    let _ = open::that(p);
                }
                if let Some(d) = open_dir {
                    let _ = open::that(d);
                }
            }

            if submit && !self.receiving {
                self.start_receive(ui.ctx());
            }
        });
    }

    // ---------- 高级设置 ----------

    fn settings_ui(&mut self, ui: &mut egui::Ui, pal: &Palette) {
        egui::CollapsingHeader::new(
            RichText::new("高级设置")
                .size(theme::TEXT_SMALL)
                .color(pal.text_muted),
        )
        .id_salt("advanced_settings")
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new("端口")
                        .size(theme::TEXT_SMALL)
                        .color(pal.text_secondary),
                );
                ui.add(egui::TextEdit::singleline(&mut self.port).desired_width(64.0));
                ui.add_space(theme::GAP);
                ui.label(
                    RichText::new("发现端口")
                        .size(theme::TEXT_SMALL)
                        .color(pal.text_secondary),
                );
                ui.add(egui::TextEdit::singleline(&mut self.discovery_port).desired_width(64.0));
            });
            ui.label(
                RichText::new(
                    "两端发现端口必须一致；修改端口会作废当前密钥，发送/接收时自动开启。",
                )
                .size(theme::TEXT_SMALL)
                .color(pal.text_muted),
            );
        });
    }
    // ---------- 接收动作 ----------

    fn start_receive(&mut self, ctx: &egui::Context) {
        let key = self.key_input.trim().to_string();
        if key.is_empty() {
            self.recv_status = Some(Status::error("请输入密钥"));
            return;
        }
        if !crate::lan::is_valid_key(&key) {
            self.recv_status = Some(Status::error(
                "密钥格式不正确：应为 8 位字母或数字（不含 I、O、0、1）",
            ));
            return;
        }
        let direct = match self.peer_ip.trim() {
            "" => None,
            raw => match raw.trim_matches(['[', ']']).parse::<IpAddr>() {
                Ok(ip) => Some(ip),
                Err(_) => {
                    self.recv_status = Some(Status::error(
                        "发送方 IP 格式不正确，应形如 192.168.1.23 或 fe80::1",
                    ));
                    return;
                }
            },
        };
        let collab = match self.ensure_started() {
            Ok(c) => c,
            Err(e) => {
                self.recv_status = Some(Status::error(e));
                return;
            }
        };
        let Some(dir) = self
            .download_dir
            .clone()
            .or_else(|| dirs::download_dir().or_else(dirs::home_dir))
        else {
            self.recv_status = Some(Status::error("无法确定下载目录，请手动选择"));
            return;
        };

        let (tx, rx) = mpsc::channel();
        let cancel = Arc::new(AtomicBool::new(false));
        let ctx_clone = ctx.clone();
        self.rx = Some(rx);
        self.cancel = Some(cancel.clone());
        self.receiving = true;
        self.recv_name = None;
        self.progress_written = 0;
        self.progress_total = 0;
        self.recv_started = Some(Instant::now());
        self.sample = None;
        self.speed = 0.0;
        self.recv_status = Some(match direct {
            Some(ip) => Status::info(format!("正在连接 {ip}…")),
            None => Status::info("正在查找持有该密钥的设备…"),
        });

        std::thread::spawn(move || {
            let found = match direct {
                Some(ip) => collab.resolve_at(&key, ip, cancel.as_ref(), Duration::from_secs(5)),
                None => collab.resolve(&key, cancel.as_ref(), Duration::from_secs(5)),
            };
            let result = found.and_then(|peer| {
                let _ = tx.send(RecvMsg::Started {
                    name: String::from_utf8_lossy(&peer.file_name).into_owned(),
                    total: peer.file_size,
                });
                let tx2 = tx.clone();
                collab.download(&peer, &dir, cancel.as_ref(), move |written, total| {
                    let _ = tx2.send(RecvMsg::Progress(written, total));
                })
            });
            match result {
                Ok(path) => {
                    let _ = tx.send(RecvMsg::Done(path));
                }
                Err(e) => {
                    let _ = tx.send(RecvMsg::Err(e));
                }
            }
            ctx_clone.request_repaint();
        });
    }

    fn eta(&self) -> String {
        if self.speed <= 1.0 || self.progress_total == 0 {
            return "—".to_string();
        }
        let remain = self.progress_total.saturating_sub(self.progress_written) as f64 / self.speed;
        if remain >= 3600.0 {
            format!("{:.1} 小时", remain / 3600.0)
        } else if remain >= 60.0 {
            format!("{} 分 {} 秒", remain as u64 / 60, remain as u64 % 60)
        } else {
            format!("{remain:.0} 秒")
        }
    }

    fn clear_history(&mut self) {
        self.received.clear();
        clear_history_log();
    }

    // ---------- 组件 ----------

    /// 保存目录：点击改目录，拖入文件/文件夹时取所在目录
    fn dir_picker(&mut self, ui: &mut egui::Ui, pal: &Palette) {
        let reserve = 52.0;
        let width = (ui.available_width() - reserve).max(120.0);
        let (rect, resp) = ui.allocate_exact_size(egui::vec2(width, 28.0), egui::Sense::click());

        let dragging = ui.input(|i| !i.raw.hovered_files.is_empty());
        self.drop_target_hover = dragging && resp.contains_pointer();
        let highlighted = self.drop_target_hover;

        let bg = if highlighted {
            pal.accent_soft
        } else if resp.hovered() {
            pal.hover
        } else {
            pal.surface_alt
        };
        let border = if highlighted { pal.accent } else { pal.border };
        {
            let painter = ui.painter();
            painter.rect_filled(rect, egui::CornerRadius::same(theme::RADIUS_SM), bg);
            painter.rect_stroke(
                rect,
                egui::CornerRadius::same(theme::RADIUS_SM),
                Stroke::new(1.0, border),
                egui::StrokeKind::Inside,
            );
            painter.text(
                egui::pos2(rect.left() + 9.0, rect.center().y),
                egui::Align2::LEFT_CENTER,
                "📂",
                egui::FontId::proportional(13.0),
                pal.text_secondary,
            );
        }

        let (text, color) = match &self.download_dir {
            Some(p) => (p.display().to_string(), pal.text),
            None => (
                "默认下载目录（可拖入文件夹更改）".to_string(),
                pal.text_muted,
            ),
        };
        let inner = egui::Rect::from_min_max(
            egui::pos2(rect.left() + 28.0, rect.top() + 4.0),
            egui::pos2(rect.right() - 6.0, rect.bottom() - 4.0),
        );
        ui.put(
            inner,
            egui::Label::new(RichText::new(&text).size(theme::TEXT_BODY).color(color))
                .truncate()
                .selectable(false),
        );

        if resp.on_hover_text(text).clicked() {
            self.open_dialog(DialogKind::DownloadDir);
        }
        if self.download_dir.is_some() && small_button(ui, "默认", pal.text_muted).clicked() {
            self.download_dir = None;
        }
    }

    fn confirm_ui(&mut self, ctx: &egui::Context) {
        let Some(confirm) = self.confirm.as_ref() else {
            return;
        };
        let title = confirm.title.clone();
        let body = confirm.body.clone();
        let action = confirm.action.clone();
        let pal = theme::palette_ctx(ctx);

        let mut confirmed = false;
        let mut close = false;
        let modal = egui::Modal::new(egui::Id::new("confirm-modal")).show(ctx, |ui| {
            ui.set_width(320.0);
            ui.label(
                RichText::new(&title)
                    .size(theme::TEXT_SECTION)
                    .strong()
                    .color(pal.text),
            );
            ui.add_space(theme::GAP_XS);
            ui.label(
                RichText::new(&body)
                    .size(theme::TEXT_BODY)
                    .color(pal.text_secondary),
            );
            ui.add_space(theme::GAP);
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if danger_button(ui, pal, "确定").clicked() {
                    confirmed = true;
                    close = true;
                }
                if secondary_button(ui, pal, "取消", true).clicked() {
                    close = true;
                }
            });
        });
        if modal.should_close() {
            close = true;
        }
        if close {
            self.confirm = None;
        }
        if confirmed {
            match action {
                ConfirmAction::Remove(key) => self.remove(&key),
                ConfirmAction::ClearHistory => {
                    self.clear_history();
                    self.recv_status = Some(Status::info("已清除接收历史"));
                }
            }
        }
    }
}

// ---------- 辅助组件 ----------

fn status_row(ui: &mut egui::Ui, pal: &Palette, status: &Status) {
    let (icon, color) = match status.kind {
        StatusKind::Info => ("•", pal.text_secondary),
        StatusKind::Ok => ("✅", pal.accent_text),
        StatusKind::Error => ("⚠", pal.danger),
    };
    ui.horizontal(|ui| {
        ui.label(RichText::new(icon).size(theme::TEXT_SMALL).color(color));
        ui.add(
            egui::Label::new(
                RichText::new(&status.text)
                    .size(theme::TEXT_SMALL)
                    .color(color),
            )
            .truncate(),
        )
        .on_hover_text(&status.text);
    });
}

/// 统一按键样式：在作用域里覆盖四种状态的填充色与文字色
#[allow(clippy::too_many_arguments)]
fn paint_button(
    ui: &mut egui::Ui,
    text: &str,
    enabled: bool,
    base: egui::Color32,
    hover: egui::Color32,
    active: egui::Color32,
    fg: egui::Color32,
    border: Stroke,
) -> egui::Response {
    ui.scope(|ui| {
        let w = &mut ui.style_mut().visuals.widgets;
        w.noninteractive.weak_bg_fill = base;
        w.noninteractive.bg_stroke = border;
        w.noninteractive.fg_stroke = Stroke::new(1.0, fg);
        w.inactive.weak_bg_fill = base;
        w.inactive.bg_stroke = border;
        w.inactive.fg_stroke = Stroke::new(1.0, fg);
        w.hovered.weak_bg_fill = hover;
        w.hovered.bg_stroke = border;
        w.hovered.fg_stroke = Stroke::new(1.0, fg);
        w.active.weak_bg_fill = active;
        w.active.bg_stroke = border;
        w.active.fg_stroke = Stroke::new(1.0, fg);
        ui.add_enabled(
            enabled,
            egui::Button::new(RichText::new(text).size(theme::TEXT_BODY).strong())
                .corner_radius(theme::RADIUS_SM)
                .min_size(egui::vec2(0.0, 30.0)),
        )
    })
    .inner
}

fn primary_button(ui: &mut egui::Ui, pal: &Palette, text: &str, enabled: bool) -> egui::Response {
    let (fill, fg) = if enabled {
        (pal.accent, pal.on_accent)
    } else {
        (pal.disabled_fill, pal.text_secondary)
    };
    paint_button(
        ui,
        text,
        enabled,
        fill,
        pal.accent_hover,
        pal.accent_active,
        fg,
        Stroke::NONE,
    )
}

fn secondary_button(ui: &mut egui::Ui, pal: &Palette, text: &str, enabled: bool) -> egui::Response {
    paint_button(
        ui,
        text,
        enabled,
        pal.surface,
        pal.hover,
        pal.accent_soft,
        pal.text,
        Stroke::new(1.0, pal.border),
    )
}

fn danger_button(ui: &mut egui::Ui, pal: &Palette, text: &str) -> egui::Response {
    paint_button(
        ui,
        text,
        true,
        pal.danger,
        pal.danger_hover,
        pal.danger_hover,
        pal.on_danger,
        Stroke::NONE,
    )
}

fn small_button(ui: &mut egui::Ui, text: &str, color: egui::Color32) -> egui::Response {
    ui.add(
        egui::Button::new(RichText::new(text).size(theme::TEXT_SMALL).color(color))
            .small()
            .corner_radius(theme::RADIUS_SM),
    )
}

// ---------- 格式化 ----------

/// 密钥按 4+4 分组，便于口头传达
fn format_key(key: &str) -> String {
    let k: String = key.chars().filter(char::is_ascii_alphanumeric).collect();
    if k.len() == 8 {
        format!("{}-{}", &k[..4], &k[4..])
    } else {
        k
    }
}

fn format_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit = 0;
    while size >= 1024.0 && unit < UNITS.len() - 1 {
        size /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{size:.1} {}", UNITS[unit])
    }
}

fn format_speed(bytes_per_sec: f64) -> String {
    if bytes_per_sec <= 0.0 {
        "—".to_string()
    } else {
        format!("{}/s", format_size(bytes_per_sec as u64))
    }
}

fn format_secs(secs: u64) -> String {
    if secs >= 60 {
        format!("{}:{:02}", secs / 60, secs % 60)
    } else {
        format!("{secs}s")
    }
}

// ---------- 接收历史（仅本地文件，不上传） ----------

fn history_log_path() -> Option<PathBuf> {
    let base = dirs::data_local_dir().or_else(dirs::home_dir)?;
    Some(base.join("secret-drop").join("history.log"))
}

fn load_history() -> Vec<String> {
    let Some(path) = history_log_path() else {
        return Vec::new();
    };
    std::fs::read_to_string(&path)
        .map(|s| {
            s.lines()
                .map(str::to_string)
                .filter(|l| !l.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

fn append_history(entry: &str) {
    let Some(path) = history_log_path() else {
        return;
    };
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&path) {
        let _ = writeln!(f, "{entry}");
    }
}

fn clear_history_log() {
    if let Some(path) = history_log_path() {
        let _ = std::fs::remove_file(path);
    }
}
