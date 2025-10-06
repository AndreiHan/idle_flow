#![cfg(windows)]
fn main() {
    println!("cargo:rerun-if-changed=../resources/manifest.xml");
    println!("cargo:rerun-if-changed=../resources/icon.ico");
    println!("cargo:rerun-if-changed=../resources/icon.png");
    tauri_winres::WindowsResource::new()
        .set_icon_with_id("../resources/icon.ico", "icon-1")
        .set_manifest_file("../resources/manifest.xml")
        .compile()
        .expect("Failed to compile Windows resources");
}
