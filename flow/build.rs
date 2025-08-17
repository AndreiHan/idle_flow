#![cfg(windows)]
fn main() {
    tauri_winres::WindowsResource::new()
        .set_icon_with_id("../resources/icon.ico", "icon-5")
        .compile()
        .expect("Failed to compile Windows resources");
}
