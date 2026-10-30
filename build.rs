fn main() {
    #[cfg(windows)]
    {
        let mut res = winresource::WindowsResource::new();
        res.set_icon("assets/icon.ico");
        res.set("ProductName", "SecretDrop");
        res.set("FileDescription", "密钥快传");
        if let Err(e) = res.compile() {
            println!("cargo:warning=嵌入 Windows 图标失败：{e}");
        }
    }
    println!("cargo:rerun-if-changed=assets/icon.ico");
}
