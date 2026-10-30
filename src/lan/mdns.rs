//! mDNS 辅助发现：UDP 定向广播在多网卡 / 防火墙环境下可能被丢弃，
//! 这里用 mDNS 组播（224.0.0.251:5353）作为补充，把 `match_id → 发送方 IP` 的映射广播出去。
//!
//! 只负责「发现地址」，拿到 IP 后仍走现有的 UDP 单播 Q/R 流程做 proof 校验，
//! 因此不会削弱原有的安全模型。

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};

pub(super) const SERVICE_TYPE: &str = "_secretdrop._udp.local.";

pub(super) fn new_daemon() -> Result<ServiceDaemon, String> {
    ServiceDaemon::new().map_err(|e| format!("启动 mDNS 失败：{e}"))
}

/// 注册一个发送方服务：实例名用 match_id 的 hex，端口是 UDP 发现端口
pub(super) fn register(
    mdns: &ServiceDaemon,
    match_id_hex: &str,
    ip: Ipv4Addr,
    discovery_port: u16,
) -> Result<String, String> {
    let info = ServiceInfo::new(
        SERVICE_TYPE,
        match_id_hex,
        &format!("{match_id_hex}.local."),
        IpAddr::V4(ip),
        discovery_port,
        &[("v", "1")][..],
    )
    .map_err(|e| format!("构造 mDNS 服务失败：{e}"))?;
    let fullname = info.get_fullname().to_string();
    mdns.register(info)
        .map_err(|e| format!("注册 mDNS 服务失败：{e}"))?;
    Ok(fullname)
}

pub(super) fn unregister(mdns: &ServiceDaemon, fullname: &str) {
    let _ = mdns.unregister(fullname);
}

/// 在超时时间内浏览 mDNS，寻找 match_id 对应的发送方 IPv4。
/// 找到后返回其地址，由调用方继续走 UDP 单播校验流程。
pub(super) fn find(
    mdns: &ServiceDaemon,
    match_id_hex: &str,
    timeout: Duration,
) -> Option<Ipv4Addr> {
    let receiver = mdns.browse(SERVICE_TYPE).ok()?;
    let deadline = Instant::now() + timeout;
    let prefix = format!("{match_id_hex}.");
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match receiver.recv_timeout(remaining) {
            Ok(ServiceEvent::ServiceResolved(info)) => {
                if info.get_fullname().starts_with(&prefix)
                    && let Some(ip) = ipv4(info.get_addresses())
                {
                    return Some(ip);
                }
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }
    None
}

fn ipv4(addresses: &HashSet<IpAddr>) -> Option<Ipv4Addr> {
    addresses.iter().find_map(|a| match a {
        IpAddr::V4(v4) if !v4.is_loopback() => Some(*v4),
        _ => None,
    })
}
