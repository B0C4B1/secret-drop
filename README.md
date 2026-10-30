# 密钥快传（SecretDrop）

[![CI](https://github.com/B0C4B1/secret-drop/actions/workflows/ci.yml/badge.svg)](https://github.com/B0C4B1/secret-drop/actions/workflows/ci.yml)

局域网内传文件的小工具：发送方选中文件后生成一次性密钥，接收方在同一局域网输入密钥即可下载。
文件不经过任何服务器，密钥只在两台设备之间线下传递。

界面基于 `eframe/egui`，单个可执行文件，无需安装；配色跟随系统浅色/深色主题。

## 工作方式

```
发送方                                    接收方
┌───────────────────┐                    ┌───────────────────┐
│ 选中文件           │                    │ 输入 8 位密钥      │
│ 生成一次性密钥     │  UDP 广播查询      │                   │
│ 监听 TCP 端口      │ ◄───────────────── │ 发现发送方         │
│                   │ ─────────────────► │ 校验应答 proof     │
│                   │  HTTP 分块密文     │ 解密并写入磁盘     │
└───────────────────┘                    └───────────────────┘
```

1. 发送方点击「选择文件」或「发送文件夹（打包）」，得到形如 `ABCD-2345` 的 8 位密钥，并把密钥告知对方；
2. 接收方输入密钥并点击「接收」，程序先在局域网内广播查询持有该密钥的设备；
3. 发送方应答并附带基于密钥派生的 `proof`，接收方验证通过后才开始下载；
4. 文件按 64 KiB 分块加密传输，接收完成后做整文件校验，密钥随即失效（一次性）。

## 安全设计

密钥永不进入网络，网络上只有它的派生物：

| 用途 | 值 | 说明 |
| --- | --- | --- |
| 主密钥 | `Argon2id(密钥, salt)` | `salt` 由密钥经 BLAKE3 派生，无需额外传输 |
| 发现匹配 | `BLAKE3(master)[..8]` | 广播查询携带，用于筛选应答，无法反推密钥 |
| 发现校验 | `keyed_hash(master, "discover" ‖ nonce)` | 只有真正持有密钥的一方才能生成，防止冒充 |
| HTTP 路径 | `keyed_hash(master, "secret-drop/token/v1")[..16]` | 请求路径中不出现密钥本身 |
| 分块加密 | XChaCha20-Poly1305 | nonce 绑定明文偏移，同一分块可重复加解密 |
| 完整性 | BLAKE3(整文件) | 发送前计算、接收后校验，静默损坏或替换都会被发现 |

- 一次性：传输完成后发送方把该记录标记为已使用，密钥立即作废；也可手动「重新生成」换新密钥。
- 过期：待接收的密钥 10 分钟后自动失效，传输中的记录给 3 倍宽限期，避免大文件中途被清理。
- 文件名不可信：接收端会去掉路径分隔符、控制字符、Windows 非法字符与保留设备名，并限制长度。

## 使用

### 发送

1. 点击「选择文件」挑一个或多个文件，多个文件会先打包成一个 zip 再传输；
2. 或点击「发送文件夹（打包）」，整个文件夹会递归打包成一个 zip（单文件仍走直传）；
   也可以把文件/文件夹直接拖到窗口里；
3. 把界面上的 8 位密钥告诉对方（可用「📋 复制密钥」）；
4. 保持程序运行，直到对方接收完成。

发送方会展示本机 IPv4/IPv6 地址，对方搜不到设备时可以直接把地址告诉对方。

### 接收

1. 输入密钥后点击「⬇ 接收」，默认保存到系统下载目录，可通过「保存到」修改（也可把文件夹拖到该处）；
2. 传输中按 `Esc` 或点「取消」可中断；
3. 广播搜不到时，展开「广播搜不到？直连发送方 IP」填写发送方地址（支持 `192.168.1.23`、`fe80::1`、`[fe80::1]`）；
4. 下载中断后再次接收会从已有 `.part` 文件继续，不会从头重传；
5. 接收历史保存在本地日志文件中，可「打开」文件或所在文件夹、「清除历史」（同时删除本地日志，不上传任何服务器）。

### 端口

| 端口 | 默认值 | 说明 |
| --- | --- | --- |
| TCP | 8765 | 发送方监听，用于传输文件；接收方不需要 |
| UDP | 7778 | 设备发现，**两端必须一致** |

发现端口在同一台电脑上只能被一个实例占用；被占用时可在界面上改成其它值（两端同步修改）。

## 网络要求

- 两台设备需在同一网段，且 AP 未开启客户端隔离；
- 系统防火墙需放行 UDP 发现端口与 TCP 传输端口（首次运行可能弹窗询问）；
- 定向广播被 AP/防火墙丢弃时，会用 mDNS 组播（224.0.0.251:5353）补充发现，找到地址后仍走 UDP 单播做 `proof` 校验；
- 跨网段、VPN、多网卡环境广播可能失效，此时使用手动直连（填 IP）；
- IPv6 仅支持**手动直连**：`if-addrs` 不提供接口索引（scope_id），链路本地 `fe80::` 地址无法自动发现。

## 下载现成程序

不需要本地装 Rust：推送 `v*` 标签（如 `git tag v0.3.0 && git push origin v0.3.0`）会触发
[Release 工作流](https://github.com/B0C4B1/secret-drop/actions/workflows/release.yml)，
自动构建四个平台的压缩包并挂到 [Releases](https://github.com/B0C4B1/secret-drop/releases) 页面。

| 平台 | 文件 |
| --- | --- |
| macOS（Apple 芯片） | `secret-drop-macos-arm64.tar.gz` |
| macOS（Intel） | `secret-drop-macos-x86_64.tar.gz` |
| Windows（x64） | `secret-drop-windows-x86_64.zip` |
| Linux（x64） | `secret-drop-linux-x86_64.tar.gz` |

也可以在 Actions 页面手动触发该工作流，产物在本次运行的 **Artifacts** 里（需登录 GitHub；Artifacts 有保留期限，Releases 长期有效）。

- macOS 版本解压后是 `SecretDrop.app`，拖到「应用程序」即可运行（图标与名称已随 .app 打包）。
  未签名，首次打开被拦下时执行 `xattr -dr com.apple.quarantine /Applications/SecretDrop.app`，或在 Finder 里右键 →「打开」；
- Linux 版本仍是动态链接，依赖系统的 GTK3 / X11 / Wayland 库（常见桌面环境已自带），缺失时按下方「构建」一节的依赖名安装。

## 构建

需要 Rust 1.88 及以上（edition 2024）。

```sh
cargo build --release   # 产物在 target/release/secret-drop
cargo run --release
```

Linux 需要 GUI 依赖（与 CI 一致）：

```sh
sudo apt-get install -y libgtk-3-dev libxkbcommon-dev \
    libxcb-render0-dev libxcb-shape0-dev libxcb-xfixes0-dev libwayland-dev
```

macOS 首次运行时系统会询问「本地网络」权限，拒绝后表现为完全搜不到设备。
精简 Linux 桌面若没有文件对话框后端，「选择文件」不会弹出窗口，可改用「手动输入文件路径」；
中文界面找不到系统 CJK 字体时会依次尝试常见字体路径并回退到 `fc-match`。

## 跨平台说明

- 非 UTF-8 文件名按原始字节传输，Unix 上可保留原样；Windows 只接受合法 UTF-8，无法落盘时会做有损替换。
- Windows 会额外处理非法字符（`< > : " | ? *`）、保留设备名（`CON`、`NUL`、`COM1` 等）与 `MAX_PATH` 长度预算。
- 平台差异集中在 [`src/platform.rs`](src/platform.rs)，文件名规则以「是否 Windows」作为参数注入，因此在 macOS/Linux 上也能跑 Windows 分支的单元测试。

## 项目结构

```
assets/              应用图标：PNG（页头）、ICO（Windows 资源）、ICNS（macOS .app）
build.rs             Windows 下把 assets/icon.ico 嵌入可执行文件
src/
├── main.rs          程序入口与窗口配置
├── app.rs           eframe::App 外壳
├── page.rs          界面：发送列表、接收流程、进度与历史
├── theme.rs         浅色/深色配色、字号、间距与中文字体
├── icon.rs          图标解码：窗口图标与页头 Logo 纹理
├── platform.rs      平台差异：文件名规则、路径长度、CJK 字体、提示文案
└── lan/
    ├── mod.rs       协作主体：分享记录、发现、下载、续传
    ├── archive.rs   多文件/文件夹打包为 zip
    ├── crypto.rs    密钥派生、token/proof、分块 nonce、hex、整文件哈希
    ├── discovery.rs UDP 报文编解码与广播地址推导
    ├── mdns.rs      mDNS 组播补充发现
    ├── server.rs    发送方 HTTP 服务（/get、/done、/abort）
    └── fsname.rs    文件名清洗与跨平台路径处理
```

## 开发

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

CI 在 Ubuntu / Windows / macOS 三个平台执行以上检查，平台专属告警同样视为失败。

## 已知限制

- 密钥只有 8 位（约 40 bit），安全性依赖「一次性 + 10 分钟有效期 + 局域网」的组合，不适合公网暴露；
- IPv6 无自动发现（mDNS 只辅助 IPv4 发现）；
- 同一台电脑同一时间只能运行一个实例（发现端口独占）。
