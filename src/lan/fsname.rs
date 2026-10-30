//! 文件名与路径处理：阻断路径穿越、临时文件命名与去重。
//!
//! 平台相关的命名规则（Windows 非法字符、保留设备名、路径长度）由
//! [`crate::platform`] 提供，这里只做与平台无关的安全校验和拼装。

use std::path::{Path, PathBuf};

use crate::platform;

/// 清洗对端给出的文件名：去掉目录部分、控制字符与平台非法字符
pub(super) fn sanitize_file_name(raw: &str) -> Option<String> {
    // 只取最后一段，彻底阻断 ../ 之类的路径穿越
    let base = raw.rsplit(['/', '\\']).next().unwrap_or("");
    let name: String = base.chars().filter(|c| !c.is_control()).collect();
    let name = platform::replace_illegal_chars(&name, platform::WINDOWS);

    // 结尾的空格和点在 Windows 上会被静默丢弃，统一先裁掉
    let name = name.trim().trim_end_matches([' ', '.']).to_string();
    if name.is_empty() || name == "." || name == ".." {
        return None;
    }
    if platform::is_reserved_name(&name, platform::WINDOWS) {
        return Some(format!("_{name}"));
    }
    Some(truncate_name(&name, 200))
}

/// 按字节上限截断，保留扩展名，且不会切断 UTF-8 字符
pub(super) fn truncate_name(name: &str, max_bytes: usize) -> String {
    if name.len() <= max_bytes {
        return name.to_string();
    }
    let (stem, ext) = split_name(name);
    let ext = if ext.len() <= 16 { ext } else { "" };
    let mut out = String::new();
    for ch in stem.chars() {
        if out.len() + ch.len_utf8() + ext.len() > max_bytes {
            break;
        }
        out.push(ch);
    }
    if out.is_empty() {
        return "download.bin".to_string();
    }
    out.push_str(ext);
    out
}

pub(super) fn split_name(name: &str) -> (&str, &str) {
    match name.rfind('.') {
        Some(i) if i > 0 => (&name[..i], &name[i..]),
        _ => (name, ""),
    }
}

/// `.part` 文件名里带上 token 前缀，避免复用别的密钥留下的半成品
pub(super) fn part_path(dest: &Path, token: &str) -> PathBuf {
    let name = dest
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    let tag = token.get(..8).unwrap_or("tmp");
    dest.with_file_name(format!(".{name}.{tag}.part"))
}

/// Windows 传统路径上限是 260 字符，先按目录长度裁掉文件名多余部分
pub(super) fn fit_to_dir(dir: &Path, name: &str) -> String {
    match platform::name_budget(dir, platform::WINDOWS) {
        Some(budget) => truncate_name(name, budget.min(200)),
        None => name.to_string(),
    }
}

pub(super) fn unique_path(dir: &Path, name: &str) -> PathBuf {
    let name = fit_to_dir(dir, name);
    let name = name.as_str();
    let direct = dir.join(name);
    if !direct.exists() {
        return direct;
    }
    let (stem, ext) = split_name(name);
    for n in 1..1000 {
        let candidate = dir.join(format!("{stem} ({n}){ext}"));
        if !candidate.exists() {
            return candidate;
        }
    }
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    dir.join(format!("{stem}-{stamp}{ext}"))
}
