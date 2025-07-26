#![cfg(windows)]
fn main() {
    let mut res = tauri_winres::WindowsResource::new();

    res.set_icon_with_id("../resources/icon.ico", "icon-5");
    #[cfg(not(debug_assertions))]
    {
        res.set_manifest_file("../resources/idler.manifest");
    }
    res.compile().unwrap();
}
