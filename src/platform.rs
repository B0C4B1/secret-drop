//! 各平台差异的集中处：文件名规则、路径长度、系统字体与权限提示。
//!
//! 文件名规则把“是否 Windows”作为参数注入，而不是在函数内部直接读 `cfg!`，
//! 这样在 macOS/Linux 上也能执行 Windows 分支的单元测试——兼容性改动不必换机器才能验证。
//! 例外：`windows_subsystem` 是 crate 级属性，只能写在 main.rs。

use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

/// 当前系统是否为 Windows
pub(crate) const WINDOWS: bool = cfg!(windows);

/// 本地文件名 → 可通过协议传输的原始字节（Unix 上文件名可以不是 UTF-8）
pub(crate) fn os_name_to_bytes(name: &OsStr) -> Vec<u8> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        name.as_bytes().to_vec()
    }
    #[cfg(not(unix))]
    {
        name.to_string_lossy().into_owned().into_bytes()
    }
}

/// 协议传来的原始字节 → 当前平台的 `OsString`；Windows 只接受合法 UTF-8
pub(crate) fn os_name_from_bytes(bytes: &[u8]) -> Option<OsString> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        Some(OsString::from_vec(bytes.to_vec()))
    }
    #[cfg(not(unix))]
    {
        String::from_utf8(bytes.to_vec()).ok().map(OsString::from)
    }
}

/// 把 Windows 不允许出现在文件名里的字符替换为下划线
pub(crate) fn replace_illegal_chars(name: &[u8], windows: bool) -> Vec<u8> {
    if !windows {
        return name.to_vec();
    }
    name.iter()
        .map(|&b| match b {
            b'<' | b'>' | b':' | b'"' | b'|' | b'?' | b'*' => b'_',
            other => other,
        })
        .collect()
}

/// Windows 保留设备名（不区分大小写，且与扩展名无关）
pub(crate) fn is_reserved_name(name: &[u8], windows: bool) -> bool {
    if !windows {
        return false;
    }
    const RESERVED: [&str; 22] = [
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
        "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];
    let end = name.iter().position(|&b| b == b'.').unwrap_or(name.len());
    let mut stem = &name[..end];
    while let [rest @ .., last] = stem {
        if !last.is_ascii_whitespace() {
            break;
        }
        stem = rest;
    }
    RESERVED
        .iter()
        .any(|r| r.as_bytes().eq_ignore_ascii_case(stem))
}

/// 目录下文件名的字节预算：Windows 受 MAX_PATH(260) 限制，其它平台不限制（返回 `None`）
pub(crate) fn name_budget(dir: &Path, windows: bool) -> Option<usize> {
    if !windows {
        return None;
    }
    // 240 给 ".part" 前后缀（最多 15 字节）和分隔符留出余量
    Some(240usize.saturating_sub(dir.as_os_str().len() + 1))
}

/// 系统 CJK 字体候选路径
pub(crate) fn cjk_font_path() -> Option<PathBuf> {
    let candidates: &[&str] = if cfg!(target_os = "macos") {
        &[
            "/System/Library/Fonts/Hiragino Sans GB.ttc",
            "/System/Library/Fonts/Supplemental/Arial Unicode.ttf",
            "/System/Library/Fonts/STHeiti Medium.ttc",
            "/System/Library/Fonts/STHeiti Light.ttc",
        ]
    } else if cfg!(windows) {
        &[
            "C:\\Windows\\Fonts\\msyh.ttc",
            "C:\\Windows\\Fonts\\msyh.ttf",
            "C:\\Windows\\Fonts\\simhei.ttf",
            "C:\\Windows\\Fonts\\simsun.ttc",
        ]
    } else {
        // Linux 等其它平台：常见 CJK 字体
        &[
            "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
            "/usr/share/fonts/noto-cjk/NotoSansCJK-Regular.ttc",
            "/usr/share/fonts/truetype/wqy/wqy-microhei.ttc",
            "/usr/share/fonts/truetype/wqy/wqy-zenhei.ttc",
            "/usr/share/fonts/wenquanyi/wqy-zenhei/wqy-zenhei.ttc",
            "/usr/share/fonts/truetype/arphic/uming.ttc",
            "/usr/share/fonts/truetype/droid/DroidSansFallbackFull.ttf",
        ]
    };

    if let Some(path) = candidates.iter().map(Path::new).find(|p| p.exists()) {
        return Some(path.to_path_buf());
    }
    // Linux 各发行版字体位置差异很大，硬编码列举不全时问 fontconfig
    if cfg!(target_os = "linux") {
        fontconfig_font()
    } else {
        None
    }
}

/// 用 `fc-match` 取系统为“中文无衬线”选中的字体文件
fn fontconfig_font() -> Option<PathBuf> {
    let out = std::process::Command::new("fc-match")
        .args(["-f", "%{file}", "sans:lang=zh"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let path = PathBuf::from(String::from_utf8_lossy(&out.stdout).trim());
    path.exists().then_some(path)
}

/// 找不到设备时附带的平台相关提示
pub(crate) fn discovery_hint() -> &'static str {
    // macOS 15 起访问本地网络需要系统授权，被拒绝时表现为完全搜不到设备
    if cfg!(target_os = "macos") {
        "；若系统询问过“本地网络”权限，请允许后重试"
    } else {
        ""
    }
}

/// 端口监听失败时附带的平台相关提示
pub(crate) fn bind_hint(port: u16) -> &'static str {
    if port < 1024 && !cfg!(windows) {
        "（1024 以下的端口需要管理员权限，请改用更大的端口）"
    } else {
        "（可能被其他程序占用，可在上方修改端口）"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn illegal_chars_only_rewritten_on_windows() {
        assert_eq!(replace_illegal_chars(b"a<b>c:d", true), b"a_b_c_d");
        assert_eq!(replace_illegal_chars(b"a<b>c:d", false), b"a<b>c:d");
    }

    #[test]
    fn reserved_names_only_on_windows() {
        assert!(is_reserved_name(b"CON", true));
        assert!(is_reserved_name(b"con.txt", true));
        assert!(!is_reserved_name(b"console", true));
        assert!(!is_reserved_name(b"CON", false));
    }

    #[test]
    fn os_name_bytes_roundtrip_preserves_utf8() {
        let raw = "中文 名字.txt".as_bytes();
        let os = os_name_from_bytes(raw).expect("合法 UTF-8 应能转成文件名");
        assert_eq!(os_name_to_bytes(&os), raw);
    }

    /// Unix 上文件名可以不是 UTF-8，非 UTF-8 字节必须原样保留
    #[cfg(unix)]
    #[test]
    fn os_name_bytes_roundtrip_preserves_non_utf8() {
        let raw = [0x66, 0x6f, 0xff, 0x6f];
        let os = os_name_from_bytes(&raw).expect("字节应能原样转成文件名");
        assert_eq!(os_name_to_bytes(&os), raw);
    }

    #[test]
    fn windows_budget_shrinks_with_directory() {
        assert_eq!(name_budget(Path::new("/tmp"), false), None);
        let long = PathBuf::from("x".repeat(300));
        assert_eq!(name_budget(&long, true), Some(0));
        assert!(name_budget(Path::new("C:\\a"), true) > name_budget(Path::new("C:\\abcdef"), true));
    }
}
