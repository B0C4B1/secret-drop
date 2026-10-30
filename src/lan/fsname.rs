//! 文件名与路径处理：阻断路径穿越、临时文件命名与去重。
//!
//! 文件名全程按**原始字节**（`&[u8]`）处理，因为 Unix 上的文件名可以不是 UTF-8，
//! 先转 `String` 会丢字符。只有在需要交给文件系统时才由 [`crate::platform`]
//! 转成 `OsString`（Windows 只接受合法 UTF-8，其它字节会退回默认名）。
//!
//! 平台相关的命名规则（Windows 非法字符、保留设备名、路径长度）也由
//! [`crate::platform`] 提供，这里只做与平台无关的安全校验和拼装。

use std::path::{Path, PathBuf};

use crate::platform;

/// 清洗后为空时的兜底文件名
const FALLBACK: &[u8] = b"download.bin";

/// 清洗对端给出的文件名：去掉目录部分、控制字符与平台非法字符
pub(super) fn sanitize_file_name(raw: &[u8]) -> Option<Vec<u8>> {
    // 只取最后一段，彻底阻断 ../ 之类的路径穿越
    let base = match raw.iter().rposition(|&b| b == b'/' || b == b'\\') {
        Some(i) => &raw[i + 1..],
        None => raw,
    };
    let name = strip_control(base);
    let name = platform::replace_illegal_chars(&name, platform::WINDOWS);

    // 结尾的空格和点在 Windows 上会被静默丢弃，统一先裁掉
    let name = trim_name(&name);
    if name.is_empty() || name == b"." || name == b".." {
        return None;
    }
    if platform::is_reserved_name(&name, platform::WINDOWS) {
        let mut prefixed = Vec::with_capacity(name.len() + 1);
        prefixed.push(b'_');
        prefixed.extend_from_slice(&name);
        return Some(prefixed);
    }
    Some(truncate_name(&name, 200))
}

/// 去掉控制字符：合法 UTF-8 时按字符判断（含 Unicode 控制符），否则只过滤 ASCII 控制字节
fn strip_control(raw: &[u8]) -> Vec<u8> {
    match std::str::from_utf8(raw) {
        Ok(s) => s
            .chars()
            .filter(|c| !c.is_control())
            .collect::<String>()
            .into_bytes(),
        Err(_) => raw
            .iter()
            .copied()
            .filter(|&b| b >= 0x20 && b != 0x7f)
            .collect(),
    }
}

/// 裁掉首尾空白，以及结尾会被 Windows 静默丢弃的空格和点
fn trim_name(raw: &[u8]) -> Vec<u8> {
    let mut start = 0;
    let mut end = raw.len();
    while start < end && raw[start].is_ascii_whitespace() {
        start += 1;
    }
    while end > start && raw[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    while end > start && (raw[end - 1] == b' ' || raw[end - 1] == b'.') {
        end -= 1;
    }
    raw[start..end].to_vec()
}

/// 按字节上限截断，保留扩展名，且不会切断 UTF-8 字符
pub(super) fn truncate_name(name: &[u8], max_bytes: usize) -> Vec<u8> {
    if name.len() <= max_bytes {
        return name.to_vec();
    }
    let (stem, ext) = split_name(name);
    let ext: &[u8] = if ext.len() <= 16 { ext } else { b"" };
    let budget = max_bytes.saturating_sub(ext.len());

    let kept = match std::str::from_utf8(stem) {
        Ok(s) => {
            let mut out = String::new();
            for ch in s.chars() {
                if out.len() + ch.len_utf8() > budget {
                    break;
                }
                out.push(ch);
            }
            out.into_bytes()
        }
        // 非 UTF-8 文件名没有字符边界可依，按字节截断即可
        Err(_) => stem[..stem.len().min(budget)].to_vec(),
    };
    if kept.is_empty() {
        return FALLBACK.to_vec();
    }
    let mut out = kept;
    out.extend_from_slice(ext);
    out
}

pub(super) fn split_name(name: &[u8]) -> (&[u8], &[u8]) {
    match name.iter().rposition(|&b| b == b'.') {
        Some(i) if i > 0 => (&name[..i], &name[i..]),
        _ => (name, b""),
    }
}

/// `.part` 文件名里带上 token 前缀，避免复用别的密钥留下的半成品
pub(super) fn part_path(dest: &Path, token: &str) -> PathBuf {
    let name = dest
        .file_name()
        .map(platform::os_name_to_bytes)
        .unwrap_or_default();
    let tag = token.get(..8).unwrap_or("tmp");
    let mut raw = Vec::with_capacity(name.len() + tag.len() + 8);
    raw.push(b'.');
    raw.extend_from_slice(&name);
    raw.push(b'.');
    raw.extend_from_slice(tag.as_bytes());
    raw.extend_from_slice(b".part");
    match platform::os_name_from_bytes(&raw) {
        Some(os) => dest.with_file_name(os),
        None => dest.with_file_name(format!(".drop.{tag}.part")),
    }
}

/// Windows 传统路径上限是 260 字符，先按目录长度裁掉文件名多余部分
pub(super) fn fit_to_dir(dir: &Path, name: &[u8]) -> Vec<u8> {
    match platform::name_budget(dir, platform::WINDOWS) {
        Some(budget) => truncate_name(name, budget.min(200)),
        None => name.to_vec(),
    }
}

pub(super) fn unique_path(dir: &Path, name: &[u8]) -> PathBuf {
    let name = fit_to_dir(dir, name);
    if let Some(direct) = join(dir, &name)
        && !direct.exists()
    {
        return direct;
    }
    let (stem, ext) = split_name(&name);
    for n in 1..1000 {
        let mut candidate = Vec::with_capacity(stem.len() + 8 + ext.len());
        candidate.extend_from_slice(stem);
        candidate.extend_from_slice(format!(" ({n})").as_bytes());
        candidate.extend_from_slice(ext);
        if let Some(path) = join(dir, &candidate)
            && !path.exists()
        {
            return path;
        }
    }
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut candidate = stem.to_vec();
    candidate.extend_from_slice(format!("-{stamp}").as_bytes());
    candidate.extend_from_slice(ext);
    join(dir, &candidate).unwrap_or_else(|| dir.join("download.bin"))
}

/// 原始字节 → 目录下的路径；Windows 上非 UTF-8 字节返回 `None`
fn join(dir: &Path, name: &[u8]) -> Option<PathBuf> {
    platform::os_name_from_bytes(name).map(|n| dir.join(n))
}
