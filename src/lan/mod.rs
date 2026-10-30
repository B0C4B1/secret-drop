//! 局域网一次性密钥传输：设备发现、分块加密传输与分享记录管理。
//!
//! 安全模型（密钥只在线下传递）：
//! - 发现请求携带 `match_id = BLAKE3(Argon2(key, salt))` 的前 8 字节，不含密钥；
//! - 发送方应答必须附带 `proof = keyed_hash(master_key, nonce)`，冒充者无法伪造；
//! - HTTP 路径使用由 `master_key` 派生的 token，而非密钥本身；
//! - 文件按 64 KiB 分块用 XChaCha20-Poly1305 加密，nonce 绑定分块偏移以支持续传，
//!   整文件再用 BLAKE3 校验，传输内容不会被静默损坏或替换。
//!
//! 模块划分：
//! - [`crypto`]：密钥派生、token/proof、分块 nonce、hex 与整文件哈希；
//! - [`discovery`]：UDP 发现报文编解码与广播地址推导；
//! - [`server`]：发送方 HTTP 服务（`/get`、`/done`、`/abort`）；
//! - [`fsname`]：文件名清洗与跨平台路径处理。

mod crypto;
mod discovery;
mod fsname;
mod server;

pub use crypto::is_valid_key;

use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime};

use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::aead::{Aead, KeyInit};

use crate::platform;

use crypto::{
    chunk_nonce, derive_key, generate_key, hash_file, hex_encode, match_id, normalize_key,
    proof_for, random_bytes, salt_for, token_for,
};
use discovery::{broadcast_targets, handle_packet};
use fsname::{part_path, sanitize_file_name, unique_path};
use server::{ConnGuard, handle_conn, http_error_text, send_abort, send_done};

const BROADCAST_PORT: u16 = 7778;
const PROTO_VERSION: &str = "1";
/// 一次性密钥的存活时间，过期后自动从分享列表移除
const SHARE_TTL: Duration = Duration::from_secs(10 * 60);
/// 同时处理的 HTTP 连接上限，避免被大量连接拖垮
const MAX_CONNECTIONS: usize = 16;

const CHUNK_SIZE: u64 = 64 * 1024;
const TAG_SIZE: u64 = 16;
const CHUNK_OVERHEAD: u64 = 4 + TAG_SIZE;
const CHUNK_WIRE: u64 = CHUNK_SIZE + CHUNK_OVERHEAD;

/// 发送列表里展示的一条分享
pub struct ShareItem {
    pub key: String,
    pub file_name: String,
    pub file_size: u64,
    pub used: bool,
    /// 距离过期还剩多少秒
    pub remaining_secs: u64,
}

/// 接收方解析到的发送方
pub struct ResolvedPeer {
    pub key: String,
    pub ip: Ipv4Addr,
    pub port: u16,
    pub file_name: String,
    pub file_size: u64,
    pub token: String,
    file_hash: [u8; 32],
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ShareState {
    Pending,
    InProgress,
    Used,
}

struct ShareRecord {
    path: PathBuf,
    file_name: String,
    file_size: u64,
    modified: Option<SystemTime>,
    master_key: [u8; 32],
    token: String,
    match_id: [u8; 8],
    file_hash: [u8; 32],
    key: String,
    state: ShareState,
    created: Instant,
}

impl ShareRecord {
    fn new(path: PathBuf) -> Result<Self, String> {
        let meta = std::fs::metadata(&path).map_err(|e| format!("无法读取文件信息：{e}"))?;
        if !meta.is_file() {
            return Err("只能发送单个文件（暂不支持文件夹）".to_string());
        }
        let raw_name = path
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .ok_or_else(|| "文件名不合法".to_string())?;
        let file_name = sanitize_file_name(&raw_name).ok_or_else(|| "文件名不合法".to_string())?;
        let file_hash = hash_file(&path)?;
        let mut rec = Self {
            path,
            file_name,
            file_size: meta.len(),
            modified: meta.modified().ok(),
            master_key: [0u8; 32],
            token: String::new(),
            match_id: [0u8; 8],
            file_hash,
            key: String::new(),
            state: ShareState::Pending,
            created: Instant::now(),
        };
        rec.rekey()?;
        Ok(rec)
    }

    /// 生成新的一次性密钥，并同步更新所有派生值
    fn rekey(&mut self) -> Result<(), String> {
        let key = generate_key()?;
        let salt = salt_for(&key);
        let master = derive_key(&key, &salt)?;
        self.token = token_for(&master);
        self.match_id = match_id(&master);
        self.master_key = master;
        self.key = key;
        self.state = ShareState::Pending;
        self.created = Instant::now();
        Ok(())
    }

    fn ttl(&self) -> Duration {
        // 传输中的记录给更长的宽限期，避免大文件中途被清理
        if self.state == ShareState::InProgress {
            SHARE_TTL * 3
        } else {
            SHARE_TTL
        }
    }

    fn expired(&self) -> bool {
        self.created.elapsed() >= self.ttl()
    }

    fn changed_on_disk(&self) -> bool {
        match std::fs::metadata(&self.path) {
            Ok(m) => {
                m.len() != self.file_size
                    || (self.modified.is_some() && m.modified().ok() != self.modified)
            }
            Err(_) => true,
        }
    }

    fn to_item(&self) -> ShareItem {
        let elapsed = self.created.elapsed().as_secs();
        ShareItem {
            key: self.key.clone(),
            file_name: self.file_name.clone(),
            file_size: self.file_size,
            used: self.state == ShareState::Used,
            remaining_secs: self.ttl().as_secs().saturating_sub(elapsed),
        }
    }
}

/// 收到但尚未校验的发现应答
#[derive(Clone)]
struct PendingPeer {
    ip: Ipv4Addr,
    port: u16,
    nonce_hex: String,
    file_name: String,
    file_size: u64,
    file_hash: [u8; 32],
    proof_hex: String,
}

/// 局域网协作：负责发现、HTTP 传输与分享记录
pub struct Collab {
    port: u16,
    running: Arc<AtomicBool>,
    shares: Arc<Mutex<HashMap<String, ShareRecord>>>,
    resolved: Arc<Mutex<HashMap<String, PendingPeer>>>,
    /// 正在等待应答的 match_id，只有这里登记的应答才被接受
    waiting: Arc<Mutex<HashSet<String>>>,
    udp: Mutex<Option<Arc<UdpSocket>>>,
    discovery_thread: Mutex<Option<JoinHandle<()>>>,
    http_thread: Mutex<Option<JoinHandle<()>>>,
    conns: Arc<AtomicUsize>,
}

impl Collab {
    pub fn new(port: u16) -> Self {
        Self {
            port,
            running: Arc::new(AtomicBool::new(false)),
            shares: Arc::new(Mutex::new(HashMap::new())),
            resolved: Arc::new(Mutex::new(HashMap::new())),
            waiting: Arc::new(Mutex::new(HashSet::new())),
            udp: Mutex::new(None),
            discovery_thread: Mutex::new(None),
            http_thread: Mutex::new(None),
            conns: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// 启动发现服务（只绑定 UDP）。接收方无需占用 TCP 端口。
    pub fn start(self: &Arc<Self>) -> Result<(), String> {
        if self.is_running() {
            return Ok(());
        }
        let udp = UdpSocket::bind(("0.0.0.0", BROADCAST_PORT)).map_err(|e| {
            format!("无法绑定发现端口 {BROADCAST_PORT}：{e}（同一台电脑上只能运行一个实例）")
        })?;
        udp.set_broadcast(true).map_err(|e| e.to_string())?;
        udp.set_read_timeout(Some(Duration::from_millis(150)))
            .map_err(|e| e.to_string())?;
        let udp = Arc::new(udp);
        *lock(&self.udp) = Some(udp.clone());
        self.running.store(true, Ordering::Relaxed);

        let me = self.clone();
        let handle = std::thread::spawn(move || {
            let mut buf = [0u8; 2048];
            while me.running.load(Ordering::Relaxed) {
                match udp.recv_from(&mut buf) {
                    Ok((n, src)) => handle_packet(&buf[..n], src, &udp, &me),
                    Err(e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::TimedOut => {}
                    Err(_) => break,
                }
            }
        });
        *lock(&self.discovery_thread) = Some(handle);
        Ok(())
    }

    /// 按需绑定 TCP 端口（只有发送方需要）
    fn ensure_http(self: &Arc<Self>) -> Result<(), String> {
        let mut guard = lock(&self.http_thread);
        if guard.is_some() {
            return Ok(());
        }
        let listener = TcpListener::bind(("0.0.0.0", self.port)).map_err(|e| {
            let hint = platform::bind_hint(self.port);
            format!("无法监听端口 {}：{e}{hint}", self.port)
        })?;
        listener.set_nonblocking(true).map_err(|e| e.to_string())?;

        let me = self.clone();
        let handle = std::thread::spawn(move || {
            while me.running.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        if me.conns.load(Ordering::Relaxed) >= MAX_CONNECTIONS {
                            let _ = stream.shutdown(Shutdown::Both);
                            continue;
                        }
                        me.conns.fetch_add(1, Ordering::Relaxed);
                        let me2 = me.clone();
                        std::thread::spawn(move || {
                            let _guard = ConnGuard(me2.conns.clone());
                            let _ = stream.set_nodelay(true);
                            handle_conn(stream, &me2);
                        });
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });
        *guard = Some(handle);
        Ok(())
    }

    /// 停止发现与 HTTP 服务
    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
        for handle in [
            lock(&self.discovery_thread).take(),
            lock(&self.http_thread).take(),
        ]
        .into_iter()
        .flatten()
        {
            let _ = handle.join();
        }
        *lock(&self.udp) = None;
    }

    pub fn maybe_auto_stop(&self) {
        if !self.has_pending() {
            self.stop();
        }
    }

    pub fn has_pending(&self) -> bool {
        let mut shares = lock(&self.shares);
        prune(&mut shares);
        // 传输中也算“忙”，否则自动关闭会把正在进行的连接掐断
        shares.values().any(|r| r.state != ShareState::Used)
    }

    pub fn list_shares(&self) -> Vec<ShareItem> {
        let mut shares = lock(&self.shares);
        prune(&mut shares);
        let mut items: Vec<ShareItem> = shares.values().map(|r| r.to_item()).collect();
        items.sort_by_key(|b| std::cmp::Reverse(b.remaining_secs));
        items
    }

    pub fn remove_share(&self, key: &str) {
        lock(&self.shares).remove(key);
    }

    /// 分享文件并返回一次性密钥
    pub fn share_file(self: &Arc<Self>, path: PathBuf) -> Result<String, String> {
        let mut rec = ShareRecord::new(path)?;
        // 只有发送方才需要监听 TCP，接收方不会占用 8765
        self.ensure_http()?;
        let mut shares = lock(&self.shares);
        prune(&mut shares);
        for _ in 0..5 {
            let dup =
                shares.contains_key(&rec.key) || shares.values().any(|r| r.token == rec.token);
            if !dup {
                break;
            }
            rec.rekey()?;
        }
        let key = rec.key.clone();
        shares.insert(key.clone(), rec);
        Ok(key)
    }

    /// 为已有记录重新生成密钥（旧密钥立即失效）
    pub fn regenerate(self: &Arc<Self>, key: &str) -> Result<String, String> {
        let mut shares = lock(&self.shares);
        prune(&mut shares);
        let Some(old) = shares.get(key) else {
            return Err("分享记录已失效".to_string());
        };
        if old.state == ShareState::InProgress {
            return Err("正在传输中，请稍后再试".to_string());
        }
        // 空闲时端口可能已自动关闭，重新生成密钥后对方仍要能连上，故先确保监听
        self.ensure_http()?;
        let mut rec = ShareRecord {
            path: old.path.clone(),
            file_name: old.file_name.clone(),
            file_size: old.file_size,
            modified: old.modified,
            master_key: [0u8; 32],
            token: String::new(),
            match_id: [0u8; 8],
            file_hash: old.file_hash,
            key: String::new(),
            state: ShareState::Pending,
            created: Instant::now(),
        };
        rec.rekey()?;
        for _ in 0..5 {
            let dup =
                shares.contains_key(&rec.key) || shares.values().any(|r| r.token == rec.token);
            if !dup {
                break;
            }
            rec.rekey()?;
        }
        let new_key = rec.key.clone();
        shares.remove(key);
        shares.insert(new_key.clone(), rec);
        Ok(new_key)
    }

    /// 通过一次性密钥在局域网内查找发送方；应答必须通过 proof 校验
    pub fn resolve(
        &self,
        key: &str,
        cancel: &AtomicBool,
        timeout: Duration,
    ) -> Result<ResolvedPeer, String> {
        self.resolve_with(key, cancel, timeout, None)
    }

    /// 直连指定的发送方，跳过广播发现。
    ///
    /// 广播在多网卡、VPN 或路由器拦截时可能不可达，这时由用户手动给出地址；
    /// 请求仍是普通 UDP 单播，proof 校验流程完全一致。
    pub fn resolve_at(
        &self,
        key: &str,
        ip: Ipv4Addr,
        cancel: &AtomicBool,
        timeout: Duration,
    ) -> Result<ResolvedPeer, String> {
        self.resolve_with(key, cancel, timeout, Some(ip))
    }

    fn resolve_with(
        &self,
        key: &str,
        cancel: &AtomicBool,
        timeout: Duration,
        direct: Option<Ipv4Addr>,
    ) -> Result<ResolvedPeer, String> {
        let key = normalize_key(key)
            .ok_or_else(|| "密钥格式不正确（应为 8 位字母或数字）".to_string())?;
        let salt = salt_for(&key);
        let master = derive_key(&key, &salt)?;
        let mid_hex = hex_encode(&match_id(&master));
        let nonce: [u8; 16] = random_bytes()?;
        let nonce_hex = hex_encode(&nonce);
        let query = format!("Q\t{PROTO_VERSION}\t{mid_hex}\t{nonce_hex}");
        let udp = lock(&self.udp)
            .clone()
            .ok_or_else(|| "发现服务未启动".to_string())?;
        let targets: Vec<SocketAddr> = match direct {
            Some(ip) => vec![SocketAddr::new(IpAddr::V4(ip), BROADCAST_PORT)],
            None => broadcast_targets()
                .into_iter()
                .map(|t| SocketAddr::new(IpAddr::V4(t), BROADCAST_PORT))
                .collect(),
        };

        lock(&self.resolved).remove(&mid_hex);
        // 登记后才接受应答，避免其它 match 的广播把结果塞进来
        lock(&self.waiting).insert(mid_hex.clone());
        let deadline = Instant::now() + timeout;
        let mut next_send = Instant::now();
        loop {
            if cancel.load(Ordering::Relaxed) {
                lock(&self.resolved).remove(&mid_hex);
                lock(&self.waiting).remove(&mid_hex);
                return Err("已取消".to_string());
            }
            if Instant::now() >= next_send {
                for target in &targets {
                    let _ = udp.send_to(query.as_bytes(), *target);
                }
                next_send = Instant::now() + Duration::from_millis(300);
            }
            let found = lock(&self.resolved).get(&mid_hex).cloned();
            if let Some(p) = found {
                let expect = hex_encode(&proof_for(&master, &nonce));
                let ok = p.nonce_hex == nonce_hex && p.proof_hex == expect;
                // 先丢掉这条应答；校验失败时保持等待，继续接受其它应答
                lock(&self.resolved).remove(&mid_hex);
                if ok {
                    lock(&self.waiting).remove(&mid_hex);
                    let file_name = sanitize_file_name(&p.file_name)
                        .unwrap_or_else(|| "download.bin".to_string());
                    return Ok(ResolvedPeer {
                        key,
                        ip: p.ip,
                        port: p.port,
                        file_name,
                        file_size: p.file_size,
                        token: token_for(&master),
                        file_hash: p.file_hash,
                    });
                }
            }
            if Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        lock(&self.resolved).remove(&mid_hex);
        lock(&self.waiting).remove(&mid_hex);
        match direct {
            Some(ip) => Err(format!(
                "无法连接 {ip}:{BROADCAST_PORT}（请确认 IP 正确、发送方仍在等待，且对方防火墙允许 UDP {BROADCAST_PORT}）"
            )),
            None => {
                let hint = platform::discovery_hint();
                Err(format!(
                    "未找到持有该密钥的设备（请确认在同一局域网，且发送方仍显示待接收）{hint}"
                ))
            }
        }
    }

    /// 本机的局域网 IPv4 地址，供对方手动直连时填写
    pub fn local_ipv4() -> Option<Ipv4Addr> {
        if_addrs::get_if_addrs()
            .ok()?
            .into_iter()
            .find_map(|iface| match iface.addr {
                if_addrs::IfAddr::V4(v4) if !v4.ip.is_loopback() && !v4.ip.is_link_local() => {
                    Some(v4.ip)
                }
                _ => None,
            })
    }

    /// 下载并解密到目标目录，返回保存路径
    pub fn download<P: FnMut(u64, u64)>(
        &self,
        peer: &ResolvedPeer,
        dest_dir: &Path,
        cancel: &AtomicBool,
        progress: P,
    ) -> Result<PathBuf, String> {
        let result = self.download_inner(peer, dest_dir, cancel, progress);
        if result.is_err() {
            // 失败或取消后主动告诉发送方释放“传输中”状态，否则对方要等宽限期结束
            send_abort(peer);
        }
        result
    }

    fn download_inner<P: FnMut(u64, u64)>(
        &self,
        peer: &ResolvedPeer,
        dest_dir: &Path,
        cancel: &AtomicBool,
        mut progress: P,
    ) -> Result<PathBuf, String> {
        let file_name =
            sanitize_file_name(&peer.file_name).ok_or_else(|| "对端文件名不合法".to_string())?;
        // 目录可能在传输途中被删除或移动
        std::fs::create_dir_all(dest_dir).map_err(|e| format!("无法创建下载目录：{e}"))?;
        let dest = unique_path(dest_dir, &file_name);
        let part = part_path(&dest, &peer.token);
        let master = derive_key(&peer.key, &salt_for(&peer.key))?;
        let cipher = XChaCha20Poly1305::new_from_slice(&master)
            .map_err(|_| "初始化解密器失败".to_string())?;
        let total = peer.file_size;

        // 续传：.part 文件名绑定 token，避免拿到别的密钥留下的半成品
        let mut raw_len = std::fs::metadata(&part).map(|m| m.len()).unwrap_or(0);
        if raw_len == total && total > 0 {
            if hash_file(&part)
                .map(|h| h == peer.file_hash)
                .unwrap_or(false)
            {
                std::fs::rename(&part, &dest).map_err(|e| format!("保存文件失败：{e}"))?;
                send_done(peer);
                progress(total, total);
                return Ok(dest);
            }
            let _ = std::fs::remove_file(&part);
            raw_len = 0;
        }
        if raw_len > total {
            // 残留文件比目标还大，说明不是同一次传输，直接丢弃
            let _ = std::fs::remove_file(&part);
            raw_len = 0;
        }

        let part_len = raw_len / CHUNK_SIZE * CHUNK_SIZE;
        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            // 续传依赖已有内容，绝不能截断
            .truncate(false)
            .open(&part)
            .map_err(|e| format!("无法写入下载目录：{e}"))?;
        file.set_len(part_len)
            .map_err(|e| format!("无法写入下载目录：{e}"))?;
        file.seek(SeekFrom::Start(part_len))
            .map_err(|e| format!("无法写入下载目录：{e}"))?;

        let mut hasher = blake3::Hasher::new();
        if part_len > 0 {
            let existing = File::open(&part).map_err(|e| format!("读取临时文件失败：{e}"))?;
            std::io::copy(&mut existing.take(part_len), &mut hasher)
                .map_err(|e| format!("读取临时文件失败：{e}"))?;
        }

        let wire_offset = part_len / CHUNK_SIZE * CHUNK_WIRE;
        let url = format!("http://{}:{}/get/{}", peer.ip, peer.port, peer.token);
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(10))
            .timeout_read(Duration::from_secs(120))
            .timeout_write(Duration::from_secs(120))
            .build();
        let mut request = agent.get(&url);
        if wire_offset > 0 {
            request = request.set("Range", &format!("bytes={wire_offset}-"));
        }
        let resp = match request.call() {
            Ok(r) => r,
            Err(ureq::Error::Status(code, _)) => return Err(http_error_text(code)),
            Err(e) => return Err(format!("连接发送方失败：{e}")),
        };
        let content_len: u64 = resp
            .header("Content-Length")
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| "响应缺少长度信息".to_string())?;

        let mut reader = resp.into_reader();
        let mut wire_left = content_len;
        let mut written = part_len;
        let mut buf = vec![0u8; (CHUNK_SIZE + TAG_SIZE) as usize];
        while wire_left > 0 {
            if cancel.load(Ordering::Relaxed) {
                return Err("已取消".to_string());
            }
            let mut head = [0u8; 4];
            reader
                .read_exact(&mut head)
                .map_err(|_| "连接中断".to_string())?;
            wire_left = wire_left.saturating_sub(4);
            let len = u32::from_le_bytes(head) as u64;
            if len > CHUNK_SIZE || len + TAG_SIZE > wire_left {
                return Err("响应数据格式错误".to_string());
            }
            let n = (len + TAG_SIZE) as usize;
            reader
                .read_exact(&mut buf[..n])
                .map_err(|_| "连接中断".to_string())?;
            wire_left -= len + TAG_SIZE;
            let nonce = chunk_nonce(&master, written);
            let plain = match cipher.decrypt(&nonce, &buf[..n]) {
                Ok(p) => p,
                Err(_) => {
                    let _ = std::fs::remove_file(&part);
                    return Err("解密失败：密钥不匹配，或发送方文件已变化".to_string());
                }
            };
            hasher.update(&plain);
            file.write_all(&plain)
                .map_err(|e| format!("写入文件失败：{e}"))?;
            written += plain.len() as u64;
            progress(written, total);
        }

        if written != total {
            return Err(format!("文件大小不一致（收到 {written}，应为 {total}）"));
        }
        if *hasher.finalize().as_bytes() != peer.file_hash {
            let _ = std::fs::remove_file(&part);
            return Err("文件校验失败，请重试".to_string());
        }
        file.flush().map_err(|e| format!("写入文件失败：{e}"))?;
        file.sync_all().map_err(|e| format!("写入文件失败：{e}"))?;
        drop(file);
        std::fs::rename(&part, &dest).map_err(|e| format!("保存文件失败：{e}"))?;
        progress(total, total);
        send_done(peer);
        Ok(dest)
    }
}
impl Drop for Collab {
    fn drop(&mut self) {
        self.stop();
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn prune(shares: &mut HashMap<String, ShareRecord>) {
    shares.retain(|_, r| !r.expired());
}

#[cfg(test)]
mod tests {
    use std::net::TcpStream;

    use super::crypto::*;
    use super::*;

    #[test]
    fn hex_roundtrip() {
        let data = [0u8, 1, 0x7f, 0xff];
        let text = hex_encode(&data);
        assert_eq!(text, "00017fff");
        assert_eq!(hex_decode(&text).unwrap(), data.to_vec());
        assert!(hex_decode("000").is_none());
        assert!(hex_decode("zz").is_none());
        assert!(hex_decode("中文").is_none());
    }

    #[test]
    fn sanitize_rejects_traversal() {
        assert_eq!(sanitize_file_name("../../etc/passwd").unwrap(), "passwd");
        assert_eq!(sanitize_file_name("C:\\tmp\\a.txt").unwrap(), "a.txt");
        assert!(sanitize_file_name("..").is_none());
        assert!(sanitize_file_name("   ").is_none());
    }

    #[test]
    fn sanitize_strips_trailing_dots() {
        assert_eq!(sanitize_file_name("report.txt. ").unwrap(), "report.txt");
    }

    #[test]
    fn sanitize_limits_length() {
        let long = format!("{}.txt", "a".repeat(400));
        let out = sanitize_file_name(&long).unwrap();
        assert!(out.len() <= 200);
        assert!(out.ends_with(".txt"));
    }

    #[test]
    fn normalize_key_accepts_case_and_separators() {
        let key = "abcd-efgh";
        assert_eq!(normalize_key(key).unwrap(), "ABCDEFGH");
        assert!(normalize_key("ABC").is_none());
        assert!(normalize_key("ABCDEFG0").is_none());
    }

    #[test]
    fn chunk_nonce_depends_on_offset() {
        let master = [7u8; 32];
        assert_ne!(
            chunk_nonce(&master, 0).as_slice(),
            chunk_nonce(&master, CHUNK_SIZE).as_slice()
        );
    }

    #[test]
    fn broadcast_targets_skip_loopback() {
        let targets = broadcast_targets();
        assert!(targets.contains(&Ipv4Addr::BROADCAST));
        assert!(targets.iter().all(|t| !t.is_loopback()));
    }

    #[test]
    fn derived_values_are_stable() {
        let key = "ABCDEFGH";
        let salt = salt_for(key);
        let master = derive_key(key, &salt).unwrap();
        assert_eq!(master, derive_key(key, &salt).unwrap());
        assert_eq!(token_for(&master).len(), 32);
        assert_eq!(match_id(&master), match_id(&master));
    }

    fn free_port() -> u16 {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.local_addr().unwrap().port()
    }

    fn http_request(port: u16, method: &str, path: &str, range: Option<u64>) -> (String, Vec<u8>) {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut req = format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\n");
        if let Some(r) = range {
            req.push_str(&format!("Range: bytes={r}-\r\n"));
        }
        req.push_str("Content-Length: 0\r\nConnection: close\r\n\r\n");
        stream.write_all(req.as_bytes()).unwrap();

        let mut resp = Vec::new();
        stream.read_to_end(&mut resp).unwrap();
        let split = resp.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
        let head = String::from_utf8_lossy(&resp[..split]).to_string();
        (head, resp[split + 4..].to_vec())
    }

    fn decrypt_body(master: &[u8; 32], start: u64, body: &[u8]) -> Vec<u8> {
        let cipher = XChaCha20Poly1305::new_from_slice(master).unwrap();
        let mut offset = start;
        let mut out = Vec::new();
        let mut i = 0;
        while i < body.len() {
            let len = u32::from_le_bytes(body[i..i + 4].try_into().unwrap()) as usize;
            i += 4;
            let ct = &body[i..i + len + TAG_SIZE as usize];
            i += len + TAG_SIZE as usize;
            let nonce = chunk_nonce(master, offset);
            out.extend_from_slice(&cipher.decrypt(&nonce, ct).unwrap());
            offset += len as u64;
        }
        out
    }

    /// 端到端：真实 HTTP 服务 + 分块加密 + Range 续传 + /done 确认
    #[test]
    fn http_transfer_roundtrip() {
        let dir = std::env::temp_dir().join(format!("secret-drop-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let src = dir.join("hello.bin");
        let data: Vec<u8> = (0..(CHUNK_SIZE * 2 + 1234))
            .map(|i| (i % 251) as u8)
            .collect();
        std::fs::write(&src, &data).unwrap();

        let port = free_port();
        let collab = Arc::new(Collab::new(port));
        collab.running.store(true, Ordering::Relaxed);
        collab.ensure_http().unwrap();
        let key = collab.share_file(src).unwrap();
        let master = derive_key(&key, &salt_for(&key)).unwrap();
        let token = token_for(&master);
        let path = format!("/get/{token}");

        let (head, body) = http_request(port, "GET", &path, None);
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        assert_eq!(decrypt_body(&master, 0, &body), data);

        // 断点续传：从第二个分块边界开始，密文偏移必须按 wire 长度对齐
        let (head, body) = http_request(port, "GET", &path, Some(CHUNK_WIRE));
        assert!(head.starts_with("HTTP/1.1 206"), "{head}");
        assert_eq!(
            decrypt_body(&master, CHUNK_SIZE, &body),
            data[CHUNK_SIZE as usize..]
        );

        // 未知 token
        let (head, _) = http_request(port, "GET", "/get/deadbeef", None);
        assert!(head.starts_with("HTTP/1.1 404"), "{head}");

        // 确认接收后密钥失效
        let (head, _) = http_request(port, "POST", &format!("/done/{token}"), None);
        assert!(head.starts_with("HTTP/1.1 200"), "{head}");
        assert!(collab.list_shares()[0].used);
        let (head, _) = http_request(port, "GET", &path, None);
        assert!(head.starts_with("HTTP/1.1 410"), "{head}");

        collab.stop();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
