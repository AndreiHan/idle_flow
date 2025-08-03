#![cfg(windows)]
fn main() {
    let mut res = tauri_winres::WindowsResource::new();
    res.set_icon_with_id("../resources/icon.ico", "icon-5");
    res.compile().unwrap();
}
