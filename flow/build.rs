#![cfg(windows)]
fn main() {
    #[cfg(debug_assertions)]
    println!("cargo:rerun-if-changed=../../.git/logs/HEAD");

    #[cfg(debug_assertions)]
    if let Ok(output) = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        && output.status.success()
    {
        let git_sha = String::from_utf8_lossy(&output.stdout);
        let git_sha = git_sha.trim();

        println!("cargo:rustc-env=GIT_COMMIT_SHA={git_sha}");
    }

    println!("cargo:rerun-if-changed=../resources/manifest.xml");
    println!("cargo:rerun-if-changed=../resources/icon.ico");
    println!("cargo:rerun-if-changed=../resources/icon.png");
    tauri_winres::WindowsResource::new()
        .set_icon_with_id("../resources/icon.ico", "clock_icon")
        .set_manifest_file("../resources/manifest.xml")
        .compile()
        .expect("Failed to compile Windows resources");
}
