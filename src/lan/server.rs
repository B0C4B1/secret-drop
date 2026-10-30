//! 发送方 HTTP 服务：流式返回分块密文，并处理接收方的完成/中止通知。

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::aead::{Aead, KeyInit};

use super::crypto::chunk_nonce;
use super::{
    CHUNK_OVERHEAD, CHUNK_SIZE, CHUNK_WIRE, Collab, ResolvedPeer, ShareState, lock, prune,
};

/// 连接计数的 RAII 守卫
pub(super) struct ConnGuard(pub(super) Arc<AtomicUsize>);

impl Drop for ConnGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// 处理一条 HTTP 连接
pub(super) fn handle_conn(mut stream: TcpStream, me: &Arc<Collab>) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(15)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(120)));

    let Ok(req) = read_request(&mut stream) else {
        return;
    };
    let path = req.path.split('?').next().unwrap_or("");

    if req.method == "POST" {
        if let Some(token) = path.strip_prefix("/done/") {
            handle_done(&mut stream, me, token);
        } else if let Some(token) = path.strip_prefix("/abort/") {
            reset_in_progress(me, token);
            http_response(&mut stream, 200, "ok");
        } else {
            http_response(&mut stream, 404, "未知路径");
        }
        return;
    }
    if req.method != "GET" {
        http_response(&mut stream, 405, "不支持的方法");
        return;
    }
    match path.strip_prefix("/get/") {
        Some(token) => handle_get(&mut stream, me, token, req.range),
        None => http_response(&mut stream, 404, "未知路径"),
    }
}

/// `GET /get/{token}`：流式返回分块密文
pub(super) fn handle_get(
    stream: &mut TcpStream,
    me: &Arc<Collab>,
    token: &str,
    range: Option<u64>,
) {
    // 在锁内取出需要的信息并标记为传输中，随后立刻放锁，避免阻塞校验线程
    let (path, size, master_key) = {
        let mut shares = lock(&me.shares);
        prune(&mut shares);
        let Some(rec) = shares.values_mut().find(|r| r.token == token) else {
            http_response(stream, 404, "分享不存在或密钥已更换");
            return;
        };
        match rec.state {
            ShareState::Used => {
                http_response(stream, 410, "该密钥已被使用");
                return;
            }
            ShareState::Pending | ShareState::InProgress => {}
        }
        if rec.changed_on_disk() {
            http_response(stream, 409, "发送方文件已变化，请重新分享");
            return;
        }
        rec.state = ShareState::InProgress;
        (rec.path.clone(), rec.file_size, rec.master_key)
    };

    let mut file = match File::open(&path) {
        Ok(f) => f,
        Err(_) => {
            reset_in_progress(me, token);
            http_response(stream, 409, "发送方无法读取该文件");
            return;
        }
    };
    let Ok(cipher) = XChaCha20Poly1305::new_from_slice(&master_key) else {
        reset_in_progress(me, token);
        return;
    };

    let total_wire = size + size.div_ceil(CHUNK_SIZE) * CHUNK_OVERHEAD;
    // 断点只对齐到分块边界，避免半块解密
    let start_wire = range.unwrap_or(0) / CHUNK_WIRE * CHUNK_WIRE;
    if start_wire >= total_wire && total_wire > 0 {
        http_response(stream, 416, "断点位置无效，请重试");
        return;
    }
    let body_len = total_wire - start_wire;
    let head = if start_wire == 0 {
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\
             Content-Length: {body_len}\r\nAccept-Ranges: bytes\r\nConnection: close\r\n\r\n"
        )
    } else {
        format!(
            "HTTP/1.1 206 Partial Content\r\nContent-Type: application/octet-stream\r\n\
             Content-Length: {body_len}\r\nContent-Range: bytes {start_wire}-{}/{total_wire}\r\n\
             Accept-Ranges: bytes\r\nConnection: close\r\n\r\n",
            total_wire.saturating_sub(1)
        )
    };
    if stream.write_all(head.as_bytes()).is_err() {
        reset_in_progress(me, token);
        return;
    }

    let mut offset = start_wire / CHUNK_WIRE * CHUNK_SIZE;
    if file.seek(SeekFrom::Start(offset)).is_err() {
        reset_in_progress(me, token);
        return;
    }

    let mut buf = vec![0u8; CHUNK_SIZE as usize];
    while offset < size {
        if !me.running.load(Ordering::Relaxed) {
            reset_in_progress(me, token);
            return;
        }
        let want = CHUNK_SIZE.min(size - offset) as usize;
        if file.read_exact(&mut buf[..want]).is_err() {
            reset_in_progress(me, token);
            return;
        }
        let nonce = chunk_nonce(&master_key, offset);
        let Ok(ct) = cipher.encrypt(&nonce, &buf[..want]) else {
            reset_in_progress(me, token);
            return;
        };
        let mut frame = Vec::with_capacity(4 + ct.len());
        frame.extend_from_slice(&(want as u32).to_le_bytes());
        frame.extend_from_slice(&ct);
        if stream.write_all(&frame).is_err() {
            // 对端断开，释放“传输中”，允许重新生成密钥或重试
            reset_in_progress(me, token);
            return;
        }
        offset += want as u64;
    }
    let _ = stream.flush();
}

/// `POST /done/{token}`：接收方确认已完整收到
pub(super) fn handle_done(stream: &mut TcpStream, me: &Arc<Collab>, token: &str) {
    let mut shares = lock(&me.shares);
    let Some(rec) = shares.values_mut().find(|r| r.token == token) else {
        drop(shares);
        http_response(stream, 404, "分享不存在");
        return;
    };
    if rec.state != ShareState::InProgress {
        drop(shares);
        http_response(stream, 409, "当前没有进行中的传输");
        return;
    }
    rec.state = ShareState::Used;
    drop(shares);
    http_response(stream, 200, "ok");
}

pub(super) fn reset_in_progress(me: &Collab, token: &str) {
    let mut shares = lock(&me.shares);
    if let Some(rec) = shares.values_mut().find(|r| r.token == token)
        && rec.state == ShareState::InProgress
    {
        rec.state = ShareState::Pending;
    }
}

/// 极简 HTTP 请求头
struct Request {
    method: String,
    path: String,
    range: Option<u64>,
}

fn read_request(stream: &mut TcpStream) -> Result<Request, String> {
    const MAX_HEAD: usize = 16 * 1024;
    let mut buf = Vec::with_capacity(512);
    let mut tmp = [0u8; 512];
    loop {
        let n = stream
            .read(&mut tmp)
            .map_err(|e| format!("读取请求失败：{e}"))?;
        if n == 0 {
            return Err("连接已关闭".to_string());
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.len() > MAX_HEAD {
            return Err("请求头过大".to_string());
        }
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }

    let text = String::from_utf8_lossy(&buf);
    let mut lines = text.split("\r\n");
    let mut first = lines.next().unwrap_or("").split(' ');
    let method = first.next().unwrap_or("").to_string();
    let path = first.next().unwrap_or("").to_string();

    let mut range = None;
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':')
            && k.trim().eq_ignore_ascii_case("range")
            && let Some(rest) = v.trim().strip_prefix("bytes=")
            && let Some((start, _)) = rest.split_once('-')
        {
            range = start.trim().parse::<u64>().ok();
        }
    }

    Ok(Request {
        method,
        path,
        range,
    })
}

pub(super) fn http_response(stream: &mut TcpStream, status: u16, body: &str) {
    let reason = match status {
        200 => "OK",
        206 => "Partial Content",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        410 => "Gone",
        416 => "Range Not Satisfiable",
        _ => "Error",
    };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(head.as_bytes());
    let _ = stream.flush();
}

pub(super) fn http_error_text(code: u16) -> String {
    match code {
        404 => "分享已失效或密钥已被更换".to_string(),
        409 => "发送方文件已变化，请让对方重新分享".to_string(),
        410 => "该密钥已被使用或已过期".to_string(),
        416 => "断点位置无效，请重试".to_string(),
        other => format!("发送方返回错误（HTTP {other}）"),
    }
}

pub(super) fn send_done(peer: &ResolvedPeer) {
    let _ = post_peer(peer, "done");
}

pub(super) fn send_abort(peer: &ResolvedPeer) {
    let _ = post_peer(peer, "abort");
}

pub(super) fn post_peer(peer: &ResolvedPeer, action: &str) -> Result<(), String> {
    let url = format!("http://{}:{}/{action}/{}", peer.ip, peer.port, peer.token);
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(5))
        .timeout_read(Duration::from_secs(5))
        .build();
    agent
        .post(&url)
        .call()
        .map(|_| ())
        .map_err(|e| e.to_string())
}
