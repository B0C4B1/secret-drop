//! 密钥快传界面：发送方生成一次性密钥，接收方输入密钥接收文件。

use std::fs::OpenOptions;
use std::io::Write;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::Duration;

use egui::{RichText, ScrollArea};

use crate::lan::{Collab, ShareItem};
use crate::theme;

pub struct TransferPage {
    port: String,
    /// UDP 发现端口，两端必须一致；7778 被占用时可改
    discovery_port: String,
    collab: Option<Arc<Collab>>,
    download_dir: Option<PathBuf>,

    key_input: String,
    /// 广播搜不到时的兜底：手动指定发送方 IPv4
    peer_ip: String,
    /// 无系统文件对话框时的兜底：手动输入文件路径
    file_path_input: String,
    received: Vec<String>,
    status: String,

    progress_written: u64,
    progress_total: u64,

    receiving: bool,
    rx: Option<mpsc::Receiver<RecvMsg>>,
    cancel: Option<Arc<AtomicBool>>,
}

enum RecvMsg {
    Progress(u64, u64),
    Done(PathBuf),
    Err(String),
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
            status: String::new(),
            progress_written: 0,
            progress_total: 0,
            receiving: false,
            rx: None,
            cancel: None,
        }
    }
}

impl TransferPage {
    pub fn ui(&mut self, ui: &mut egui::Ui) {
        self.poll(ui.ctx());
        self.auto_stop();

        page_header(ui, "密钥快传", "生成一次性密钥，对方输入密钥即可接收文件");

        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.label(RichText::new("端口：").color(theme::TEXT_SECONDARY));
            ui.add(egui::TextEdit::singleline(&mut self.port).desired_width(70.0));
            ui.add_space(10.0);
            ui.label(RichText::new("发现端口：").color(theme::TEXT_SECONDARY));
            ui.add(egui::TextEdit::singleline(&mut self.discovery_port).desired_width(70.0));
        });
        ui.label(
            RichText::new("发送/接收时自动开启，空闲时关闭；两台设备的发现端口必须相同")
                .size(11.0)
                .color(theme::TEXT_MUTED),
        );
        ui.label(RichText::new("下载目录：").color(theme::TEXT_SECONDARY));
        dir_picker(ui, &mut self.download_dir);

        if !self.status.is_empty() {
            ui.add_space(4.0);
            ui.label(
                RichText::new(&self.status)
                    .size(12.0)
                    .color(theme::TEXT_SECONDARY),
            );
        }

        ui.add_space(4.0);
        ui.separator();
        self.share_ui(ui);

        ui.add_space(4.0);
        ui.separator();
        self.receive_ui(ui);
    }

    fn poll(&mut self, ctx: &egui::Context) {
        let mut finished = false;
        if let Some(rx) = &self.rx {
            loop {
                match rx.try_recv() {
                    Ok(RecvMsg::Progress(w, t)) => {
                        self.progress_written = w;
                        self.progress_total = t;
                        if w > 0 {
                            self.status = "正在接收…".to_string();
                        }
                    }
                    Ok(RecvMsg::Done(p)) => {
                        self.received.push(p.display().to_string());
                        append_history(&p.display().to_string());
                        self.status = "接收完成".to_string();
                        self.key_input.clear();
                        self.receiving = false;
                        self.cancel = None;
                        finished = true;
                    }
                    Ok(RecvMsg::Err(e)) => {
                        self.status = if e == "已取消" {
                            "已取消".to_string()
                        } else {
                            format!("接收失败：{e}")
                        };
                        self.receiving = false;
                        self.cancel = None;
                        finished = true;
                    }
                    Err(mpsc::TryRecvError::Empty) => break,
                    Err(mpsc::TryRecvError::Disconnected) => {
                        self.receiving = false;
                        self.cancel = None;
                        finished = true;
                        break;
                    }
                }
            }
        }
        if finished {
            self.rx = None;
        }
        if self.receiving {
            ctx.request_repaint();
        }
    }

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

    fn pick_and_share(&mut self) {
        match rfd::FileDialog::new().pick_files() {
            Some(files) if !files.is_empty() => {
                self.share_paths(files);
            }
            // 没有 xdg-desktop-portal 的精简 Linux 桌面上会直接返回 None，
            // 与“用户取消”无法区分，所以只给指引，不当作错误
            _ => {
                self.status =
                    "未选择文件；若没有弹出对话框，请展开下方“手动输入文件路径”".to_string()
            }
        }
    }

    fn pick_folder_and_share(&mut self) {
        match rfd::FileDialog::new().pick_folder() {
            Some(dir) => {
                self.share_paths(vec![dir]);
            }
            None => self.status = "未选择文件夹".to_string(),
        }
    }

    fn share_path(&mut self) {
        let raw = self.file_path_input.trim();
        if raw.is_empty() {
            self.status = "请输入文件路径".to_string();
            return;
        }
        let file = PathBuf::from(raw);
        if !file.is_file() {
            self.status = format!("路径不存在或不是文件：{}", file.display());
            return;
        }
        let collab = match self.ensure_started() {
            Ok(c) => c,
            Err(e) => {
                self.status = e;
                return;
            }
        };
        match collab.share_file(file) {
            Ok(key) => {
                self.status = format!("已生成密钥：{key}（请告知对方）");
                self.file_path_input.clear();
            }
            Err(e) => self.status = e,
        }
    }

    fn share_paths(&mut self, paths: Vec<PathBuf>) -> bool {
        let collab = match self.ensure_started() {
            Ok(c) => c,
            Err(e) => {
                self.status = e;
                return false;
            }
        };
        match collab.share_paths(paths) {
            Ok(key) => {
                self.status = format!("已生成密钥：{key}（请告知对方）");
                true
            }
            Err(e) => {
                self.status = e;
                false
            }
        }
    }

    fn regenerate(&mut self, key: &str) {
        let collab = match self.ensure_started() {
            Ok(c) => c,
            Err(e) => {
                self.status = e;
                return;
            }
        };
        match collab.regenerate(key) {
            Ok(new) => self.status = format!("已重新生成密钥：{new}"),
            Err(e) => self.status = e,
        }
    }

    fn remove(&mut self, key: &str) {
        if let Some(c) = &self.collab {
            c.remove_share(key);
        }
    }

    fn start_receive(&mut self, ctx: &egui::Context) {
        let key = self.key_input.trim().to_string();
        if key.is_empty() {
            self.status = "请输入密钥".to_string();
            return;
        }
        if !crate::lan::is_valid_key(&key) {
            self.status = "密钥格式不正确：应为 8 位字母或数字（不含 I、O、0、1）".to_string();
            return;
        }
        let direct = match self.peer_ip.trim() {
            "" => None,
            raw => match raw.trim_matches(['[', ']']).parse::<IpAddr>() {
                Ok(ip) => Some(ip),
                Err(_) => {
                    self.status =
                        "发送方 IP 格式不正确，应形如 192.168.1.23 或 fe80::1".to_string();
                    return;
                }
            },
        };
        let collab = match self.ensure_started() {
            Ok(c) => c,
            Err(e) => {
                self.status = e;
                return;
            }
        };
        let Some(dir) = self
            .download_dir
            .clone()
            .or_else(|| dirs::download_dir().or_else(dirs::home_dir))
        else {
            self.status = "无法确定下载目录".to_string();
            return;
        };

        let (tx, rx) = mpsc::channel();
        let cancel = Arc::new(AtomicBool::new(false));
        let ctx_clone = ctx.clone();
        self.rx = Some(rx);
        self.cancel = Some(cancel.clone());
        self.receiving = true;
        self.progress_written = 0;
        self.progress_total = 0;
        self.status = match direct {
            Some(ip) => format!("正在连接 {ip}…"),
            None => "正在查找持有该密钥的设备…".to_string(),
        };

        std::thread::spawn(move || {
            let found = match direct {
                Some(ip) => collab.resolve_at(&key, ip, cancel.as_ref(), Duration::from_secs(5)),
                None => collab.resolve(&key, cancel.as_ref(), Duration::from_secs(5)),
            };
            let result = found.and_then(|peer| {
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

    fn clear_history(&mut self) {
        self.received.clear();
        clear_history_log();
    }

    fn share_ui(&mut self, ui: &mut egui::Ui) {
        ui.add_space(6.0);
        ui.label(
            RichText::new("发送文件")
                .size(14.0)
                .strong()
                .color(theme::TEXT),
        );
        ui.horizontal(|ui| {
            if ui
                .add_enabled(!self.receiving, primary_button("选择文件（可多选）"))
                .clicked()
            {
                self.pick_and_share();
            }
            if ui
                .add_enabled(!self.receiving, primary_button("发送文件夹（打包）"))
                .clicked()
            {
                self.pick_folder_and_share();
            }
        });

        // 精简 Linux 桌面可能没有文件对话框后端，留一条手动输入的退路
        egui::CollapsingHeader::new(
            RichText::new("手动输入文件路径")
                .size(11.0)
                .color(theme::TEXT_MUTED),
        )
        .id_salt("manual_file_path")
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut self.file_path_input)
                        .hint_text("没有弹出选择框时可在这里输入完整路径")
                        .desired_width(320.0),
                );
                if ui
                    .add_enabled(!self.receiving, egui::Button::new("分享"))
                    .clicked()
                {
                    self.share_path();
                }
            });
        });

        let items: Vec<ShareItem> = self
            .collab
            .as_ref()
            .map(|c| c.list_shares())
            .unwrap_or_default();
        if items.is_empty() {
            return;
        }

        if let Some(ip) = Collab::local_ipv4() {
            ui.label(
                RichText::new(format!("本机地址：{ip}（对方搜不到时可直接填这个 IP）"))
                    .size(11.0)
                    .color(theme::TEXT_MUTED),
            );
        }
        if let Some(ip) = Collab::local_ipv6() {
            ui.label(
                RichText::new(format!("本机 IPv6：{ip}"))
                    .size(11.0)
                    .color(theme::TEXT_MUTED),
            );
        }

        let mut regen: Option<String> = None;
        let mut remove: Option<String> = None;
        let mut copy: Option<String> = None;
        ui.add_space(4.0);
        ScrollArea::vertical()
            .auto_shrink([false, false])
            .max_height(160.0)
            .show(ui, |ui| {
                for it in &items {
                    ui.horizontal(|ui| {
                        let status = if it.used {
                            RichText::new("已接收").color(theme::TEXT_MUTED)
                        } else {
                            RichText::new(format!("待接收 · 剩 {}", format_secs(it.remaining_secs)))
                                .color(theme::ACCENT_TEXT)
                        };
                        ui.label(
                            RichText::new(format!(
                                "{} · {}",
                                it.file_name,
                                format_size(it.file_size)
                            ))
                            .size(12.0)
                            .color(theme::TEXT),
                        );
                        ui.label(
                            RichText::new(&it.key)
                                .size(13.0)
                                .strong()
                                .color(theme::ACCENT_TEXT),
                        );
                        if ui.small_button("复制").clicked() {
                            copy = Some(it.key.clone());
                        }
                        ui.label(status.size(11.0));
                        if ui.small_button("重新生成").clicked() {
                            regen = Some(it.key.clone());
                        }
                        if ui.small_button("移除").clicked() {
                            remove = Some(it.key.clone());
                        }
                    });
                }
            });
        if let Some(k) = copy {
            ui.ctx().copy_text(k.clone());
            self.status = format!("已复制密钥：{k}");
        }
        if let Some(k) = regen {
            self.regenerate(&k);
        }
        if let Some(k) = remove {
            self.remove(&k);
        }
    }

    fn receive_ui(&mut self, ui: &mut egui::Ui) {
        ui.add_space(6.0);
        ui.label(
            RichText::new("接收文件")
                .size(14.0)
                .strong()
                .color(theme::TEXT),
        );
        ui.horizontal(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut self.key_input)
                    .hint_text("输入 8 位密钥，如 ABCD2345")
                    .desired_width(180.0),
            );
            if ui
                .add_enabled(!self.receiving, primary_button("接收"))
                .clicked()
            {
                self.start_receive(ui.ctx());
            }
        });

        // 广播在多网卡/VPN/防火墙环境下可能搜不到对端，直连可绕过发现阶段
        egui::CollapsingHeader::new(
            RichText::new("广播搜不到？直连发送方 IP")
                .size(11.0)
                .color(theme::TEXT_MUTED),
        )
        .id_salt("manual_peer_ip")
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut self.peer_ip)
                        .hint_text("留空自动搜索，例如 192.168.1.23 或 fe80::1")
                        .desired_width(240.0),
                );
                ui.label(
                    RichText::new("填上方发送方的局域网地址")
                        .size(11.0)
                        .color(theme::TEXT_MUTED),
                );
            });
        });
        if self.receiving {
            ui.horizontal(|ui| {
                ui.add(egui::Spinner::new());
                ui.label(
                    RichText::new(&self.status)
                        .size(12.0)
                        .color(theme::TEXT_SECONDARY),
                );
                if ui.small_button("取消").clicked()
                    && let Some(c) = &self.cancel
                {
                    c.store(true, Ordering::Relaxed);
                }
            });
            if self.progress_total > 0 {
                let frac =
                    (self.progress_written as f32 / self.progress_total as f32).clamp(0.0, 1.0);
                ui.add(
                    egui::ProgressBar::new(frac)
                        .fill(theme::ACCENT)
                        .text(format!(
                            "{} / {}",
                            format_size(self.progress_written),
                            format_size(self.progress_total)
                        )),
                );
            }
        }

        if !self.received.is_empty() {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new("接收历史")
                        .size(12.0)
                        .color(theme::TEXT_SECONDARY),
                );
                if ui.small_button("清除历史").clicked() {
                    self.clear_history();
                }
            });
            ScrollArea::vertical()
                .auto_shrink([false, false])
                .max_height(120.0)
                .show(ui, |ui| {
                    let mut open_file: Option<PathBuf> = None;
                    let mut open_dir: Option<PathBuf> = None;
                    for p in &self.received {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(p).size(11.0).color(theme::TEXT));
                            if ui.small_button("打开").clicked() {
                                open_file = Some(PathBuf::from(p));
                            }
                            if ui.small_button("文件夹").clicked() {
                                if let Some(dir) = PathBuf::from(p).parent() {
                                    open_dir = Some(dir.to_path_buf());
                                }
                            }
                        });
                    }
                    if let Some(p) = open_file {
                        let _ = open::that(&p);
                    }
                    if let Some(d) = open_dir {
                        let _ = open::that(&d);
                    }
                });
        }
    }
}

// ---------- 辅助函数（从原工程抽取的最小集合） ----------

/// 接收历史日志路径：本地文件，不上传任何服务器或数据库
fn history_log_path() -> Option<PathBuf> {
    let base = dirs::data_local_dir().or_else(dirs::home_dir)?;
    Some(base.join("secret-drop").join("history.log"))
}

/// 启动时读取本地日志，恢复接收历史
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

/// 每次接收完成追加一行到本地日志
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

/// 清理历史：同时删除本地日志文件
fn clear_history_log() {
    if let Some(path) = history_log_path() {
        let _ = std::fs::remove_file(path);
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

fn format_secs(secs: u64) -> String {
    if secs >= 60 {
        format!("{}:{:02}", secs / 60, secs % 60)
    } else {
        format!("{secs}s")
    }
}

/// 主操作按钮（绿底深字）
fn primary_button(text: impl Into<String>) -> egui::Button<'static> {
    egui::Button::new(RichText::new(text.into()).strong().color(theme::TEXT)).fill(theme::ACCENT)
}

/// 页头：标题 + 说明
fn page_header(ui: &mut egui::Ui, title: &str, desc: &str) {
    ui.add_space(6.0);
    ui.label(RichText::new(title).size(17.0).strong().color(theme::TEXT));
    ui.add_space(2.0);
    ui.label(RichText::new(desc).size(12.0).color(theme::TEXT_SECONDARY));
}

/// 目录选择器，支持拖拽和点击
fn dir_picker(ui: &mut egui::Ui, path: &mut Option<PathBuf>) -> bool {
    let mut changed = false;

    ui.horizontal(|ui| {
        let reserve_clear = path.is_some();
        let desired = egui::vec2(
            (ui.available_width() - if reserve_clear { 48.0 } else { 0.0 }).max(120.0),
            34.0,
        );
        let (rect, response) = ui.allocate_exact_size(desired, egui::Sense::click());

        let hovering_file = ui.input(|i| !i.raw.hovered_files.is_empty());
        let pointer_over = response.contains_pointer();

        let bg = if pointer_over && hovering_file {
            theme::ACCENT_SOFT
        } else if pointer_over {
            theme::HOVER
        } else {
            theme::SURFACE
        };
        let border = if pointer_over {
            theme::ACCENT
        } else {
            theme::BORDER
        };

        let painter = ui.painter();
        painter.rect_filled(rect, egui::CornerRadius::same(4), bg);
        painter.rect_stroke(
            rect,
            egui::CornerRadius::same(4),
            egui::Stroke::new(1.0, border),
            egui::StrokeKind::Inside,
        );

        let color = if path.is_some() {
            theme::TEXT
        } else {
            theme::TEXT_MUTED
        };
        match path.as_ref() {
            Some(p) => {
                painter.text(
                    egui::pos2(rect.left() + 10.0, rect.center().y),
                    egui::Align2::LEFT_CENTER,
                    p.display().to_string(),
                    egui::FontId::proportional(12.0),
                    color,
                );
            }
            None => {
                painter.text(
                    rect.center(),
                    egui::Align2::CENTER_CENTER,
                    "拖拽文件夹到此处，或点击选择",
                    egui::FontId::proportional(12.0),
                    color,
                );
            }
        }

        if path.is_some() && ui.button("清除").clicked() {
            *path = None;
            changed = true;
        }

        // 拖放：文件取父目录，目录直接采用
        let dropped = ui.input(|i| i.raw.dropped_files.clone());
        if !dropped.is_empty() {
            let p = dropped[0].path().to_path_buf();
            let dir = if p.is_dir() {
                p
            } else {
                p.parent().unwrap_or(&p).to_path_buf()
            };
            *path = Some(dir);
            changed = true;
        } else if response.clicked() {
            // 点击弹出选择框
            if let Some(p) = rfd::FileDialog::new().pick_folder() {
                *path = Some(p);
                changed = true;
            }
        }
    });

    changed
}
