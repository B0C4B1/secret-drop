//! 多文件 / 文件夹打包：把一组路径递归压成一个临时 zip，供单文件传输通道复用。

use std::fs::File;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

/// 把一组文件 / 目录打包成单个 zip，返回临时 zip 的路径。
///
/// 打包结果放在系统临时目录，分享结束（移除或过期）后由调用方负责清理。
pub(super) fn zip_paths(paths: &[PathBuf], base_name: &str) -> Result<PathBuf, String> {
    let entries = collect(paths)?;
    if entries.is_empty() {
        return Err("没有可打包的文件".to_string());
    }

    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let tmp = std::env::temp_dir().join(format!("{base_name}-{stamp}-{}.zip", std::process::id()));

    let file = File::create(&tmp).map_err(|e| format!("无法创建临时文件：{e}"))?;
    let mut zip = ZipWriter::new(file);
    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .unix_permissions(0o644);

    for (rel, path) in &entries {
        zip.start_file(rel.clone(), options)
            .map_err(|e| format!("打包失败：{e}"))?;
        let mut f = File::open(path).map_err(|e| format!("无法读取文件：{e}"))?;
        std::io::copy(&mut f, &mut zip).map_err(|e| format!("打包失败：{e}"))?;
    }
    zip.finish().map_err(|e| format!("打包失败：{e}"))?;
    Ok(tmp)
}

/// 收集待打包项，返回（zip 内相对路径，文件系统绝对路径）
fn collect(paths: &[PathBuf]) -> Result<Vec<(String, PathBuf)>, String> {
    let mut out = Vec::new();
    for p in paths {
        let name = p
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "item".to_string());
        if p.is_file() {
            out.push((name, p.clone()));
        } else if p.is_dir() {
            collect_dir(p, &name, &mut out)?;
        } else {
            return Err(format!("无法读取：{}", p.display()));
        }
    }
    Ok(out)
}

fn collect_dir(dir: &Path, prefix: &str, out: &mut Vec<(String, PathBuf)>) -> Result<(), String> {
    for entry in std::fs::read_dir(dir).map_err(|e| format!("无法读取目录：{e}"))? {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        let rel = format!("{prefix}/{name}");
        if path.is_dir() {
            collect_dir(&path, &rel, out)?;
        } else if path.is_file() {
            out.push((rel, path));
        }
    }
    Ok(())
}
