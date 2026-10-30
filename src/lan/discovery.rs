//! UDP 发现协议：查询/应答报文的编解码与广播地址推导。

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Arc;

use super::crypto::{hex_decode, hex_decode_arr, hex_encode, proof_for};
use super::{Collab, PROTO_VERSION, PendingPeer, ShareState, lock, prune};

/// 发现报文分发：Q = 查询，R = 应答
pub(super) fn handle_packet(buf: &[u8], src: SocketAddr, udp: &UdpSocket, me: &Arc<Collab>) {
    let Ok(text) = std::str::from_utf8(buf) else {
        return;
    };
    let parts: Vec<&str> = text.split('\t').collect();
    match parts.first() {
        Some(&"Q") => handle_query(&parts, src, udp, me),
        Some(&"R") => handle_reply(&parts, src, me),
        _ => {}
    }
}

/// 查询：`Q\tv1\t{match_hex}\t{nonce_hex}`
pub(super) fn handle_query(parts: &[&str], src: SocketAddr, udp: &UdpSocket, me: &Arc<Collab>) {
    if parts.len() < 4 || parts[1] != PROTO_VERSION {
        return;
    }
    let Some(mid) = hex_decode_arr::<8>(parts[2]) else {
        return;
    };
    let Some(nonce) = hex_decode(parts[3]) else {
        return;
    };
    if nonce.len() != 16 {
        return;
    }

    let reply = {
        let mut shares = lock(&me.shares);
        prune(&mut shares);
        shares
            .values()
            .find(|r| r.match_id == mid && r.state == ShareState::Pending)
            .map(|r| {
                let proof = hex_encode(&proof_for(&r.master_key, &nonce));
                format!(
                    "R\t{PROTO_VERSION}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                    parts[2],
                    parts[3],
                    hex_encode(&r.file_name),
                    r.file_size,
                    me.port,
                    hex_encode(&r.file_hash),
                    proof
                )
            })
    };
    if let Some(reply) = reply {
        let _ = udp.send_to(reply.as_bytes(), src);
    }
}

/// 解析后的应答，尚未做 proof 校验
pub(super) struct Reply {
    pub mid: [u8; 8],
    pub nonce_hex: String,
    pub file_name: Vec<u8>,
    pub file_size: u64,
    pub port: u16,
    pub file_hash: [u8; 32],
    pub proof_hex: String,
}

/// 应答：`R\tv1\t{match}\t{nonce}\t{name_hex}\t{size}\t{port}\t{hash_hex}\t{proof_hex}`
pub(super) fn parse_reply(parts: &[&str]) -> Option<Reply> {
    if parts.len() < 9 || parts[1] != PROTO_VERSION {
        return None;
    }
    let mid = hex_decode_arr::<8>(parts[2])?;
    let nonce_hex = parts[3];
    if nonce_hex.len() != 32 {
        return None;
    }
    // 文件名按原始字节接收，非 UTF-8 名字也原样保留
    let file_name = hex_decode(parts[4])?;
    let file_size = parts[5].parse::<u64>().ok()?;
    let port = parts[6].parse::<u16>().ok()?;
    let file_hash = hex_decode_arr::<32>(parts[7])?;
    let proof_hex = parts[8];
    if proof_hex.len() != 64 {
        return None;
    }
    Some(Reply {
        mid,
        nonce_hex: nonce_hex.to_string(),
        file_name,
        file_size,
        port,
        file_hash,
        proof_hex: proof_hex.to_string(),
    })
}

pub(super) fn handle_reply(parts: &[&str], src: SocketAddr, me: &Arc<Collab>) {
    let Some(reply) = parse_reply(parts) else {
        return;
    };
    let mid_hex = hex_encode(&reply.mid);
    // 只接受当前正在解析的 match，避免被无关或伪造的应答污染
    if !lock(&me.waiting).contains(&mid_hex) {
        return;
    }
    lock(&me.resolved).insert(
        mid_hex,
        PendingPeer {
            ip: src.ip(),
            port: reply.port,
            nonce_hex: reply.nonce_hex,
            file_name: reply.file_name,
            file_size: reply.file_size,
            file_hash: reply.file_hash,
            proof_hex: reply.proof_hex,
        },
    );
}

/// 发现报文要发往的地址。
///
/// 多网卡、VPN 环境下 `255.255.255.255` 只从默认路由所在网卡发出，
/// 因此枚举本机所有 IPv4 网卡，各自算出定向广播地址，覆盖每个网段。
pub(super) fn broadcast_targets() -> Vec<Ipv4Addr> {
    let mut targets = vec![Ipv4Addr::BROADCAST];
    if let Ok(ifaces) = if_addrs::get_if_addrs() {
        for iface in ifaces {
            let if_addrs::IfAddr::V4(v4) = iface.addr else {
                continue;
            };
            let mask = u32::from(v4.netmask);
            // 回环、链路本地和未配置掩码的网卡广播没有意义
            if v4.ip.is_loopback() || mask == 0 {
                continue;
            }
            targets.push(Ipv4Addr::from(u32::from(v4.ip) | !mask));
        }
    }
    targets.sort_unstable();
    targets.dedup();
    targets
}
