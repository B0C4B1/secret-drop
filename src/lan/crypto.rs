//! 密钥派生与编解码：Argon2id 主密钥、token/proof、分块 nonce、hex 与整文件哈希。

use std::fs::File;
use std::io::Read;
use std::path::Path;

use argon2::Argon2;
use chacha20poly1305::XNonce;

const KEY_LEN: usize = 8;
const KEY_ALPHABET: &[u8; 32] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

pub(super) fn random_bytes<const N: usize>() -> Result<[u8; N], String> {
    let mut out = [0u8; N];
    getrandom::getrandom(&mut out).map_err(|e| format!("随机数生成失败：{e}"))?;
    Ok(out)
}

/// 生成 8 位一次性密钥（32 个字符的字母表，按位取模无偏）
pub(super) fn generate_key() -> Result<String, String> {
    let bytes: [u8; KEY_LEN] = random_bytes()?;
    Ok(bytes
        .iter()
        .map(|b| KEY_ALPHABET[(b & 31) as usize] as char)
        .collect())
}

/// 校验用户输入的密钥格式（不区分大小写，允许空白与 `-`/`_` 分隔）
pub fn is_valid_key(raw: &str) -> bool {
    normalize_key(raw).is_some()
}

/// 规范化用户输入的密钥：去掉空白与分隔符、转大写、校验字符集
pub(super) fn normalize_key(raw: &str) -> Option<String> {
    let cleaned: String = raw
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-' && *c != '_')
        .collect();
    let cleaned = cleaned.to_ascii_uppercase();
    if cleaned.len() != KEY_LEN {
        return None;
    }
    if cleaned.bytes().any(|b| !KEY_ALPHABET.contains(&b)) {
        return None;
    }
    Some(cleaned)
}

pub(super) fn salt_for(key: &str) -> [u8; 16] {
    let digest = blake3::hash(format!("secret-drop/salt/v1/{key}").as_bytes());
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&digest.as_bytes()[..16]);
    salt
}

pub(super) fn derive_key(key: &str, salt: &[u8; 16]) -> Result<[u8; 32], String> {
    let mut out = [0u8; 32];
    Argon2::default()
        .hash_password_into(key.as_bytes(), salt, &mut out)
        .map_err(|e| format!("密钥派生失败：{e}"))?;
    Ok(out)
}

pub(super) fn match_id(master: &[u8; 32]) -> [u8; 8] {
    let digest = blake3::hash(master);
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest.as_bytes()[..8]);
    out
}

pub(super) fn token_for(master: &[u8; 32]) -> String {
    let digest = blake3::keyed_hash(master, b"secret-drop/token/v1");
    hex_encode(&digest.as_bytes()[..16])
}

pub(super) fn proof_for(master: &[u8; 32], nonce: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(8 + nonce.len());
    input.extend_from_slice(b"discover");
    input.extend_from_slice(nonce);
    *blake3::keyed_hash(master, &input).as_bytes()
}

/// 分块 nonce 绑定明文偏移，续传时同一分块可重复加解密
pub(super) fn chunk_nonce(master: &[u8; 32], offset: u64) -> XNonce {
    let mut input = [0u8; 16];
    input[..8].copy_from_slice(b"chunk-v1");
    input[8..].copy_from_slice(&offset.to_le_bytes());
    let digest = blake3::keyed_hash(master, &input);
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&digest.as_bytes()[..24]);
    *XNonce::from_slice(&nonce)
}

pub(super) fn hash_file(path: &Path) -> Result<[u8; 32], String> {
    let mut file = File::open(path).map_err(|e| format!("无法读取文件：{e}"))?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| format!("无法读取文件：{e}"))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(*hasher.finalize().as_bytes())
}

const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

pub(super) fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX_CHARS[(b >> 4) as usize] as char);
        out.push(HEX_CHARS[(b & 0x0f) as usize] as char);
    }
    out
}

pub(super) fn hex_decode(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for i in (0..bytes.len()).step_by(2) {
        out.push((hex_val(bytes[i])? << 4) | hex_val(bytes[i + 1])?);
    }
    Some(out)
}

pub(super) fn hex_decode_arr<const N: usize>(text: &str) -> Option<[u8; N]> {
    if text.len() != N * 2 {
        return None;
    }
    let bytes = hex_decode(text)?;
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Some(out)
}

pub(super) fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}
