use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/index");
    // The Docker builder has no .git, so the version arrives as an env var; the
    // target cache mount persists across builds and would otherwise keep the
    // previously stamped version.
    println!("cargo:rerun-if-env-changed=GIT_VERSION");

    let git_version = get_git_version();
    println!("cargo:rustc-env=GIT_VERSION={git_version}");

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR not set"));
    render_apple_touch_icon(&out_dir);
}

fn render_apple_touch_icon(out_dir: &Path) {
    use resvg::{tiny_skia, usvg};

    let manifest_dir =
        PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set"));
    let svg_path = manifest_dir.join("admin-ui/dist/favicon.svg");
    println!("cargo:rerun-if-changed=admin-ui/dist/favicon.svg");

    let svg_str = fs::read_to_string(&svg_path).expect("failed to read favicon.svg");
    // Strip the source SVG's rounded-corner so iOS applies its own
    // superellipse mask cleanly without a double-radius artefact.
    let svg_str = svg_str.replace(r#" rx="6""#, "").replace(r#" ry="6""#, "");

    let tree = usvg::Tree::from_str(&svg_str, &usvg::Options::default())
        .expect("failed to parse favicon.svg");

    let size: u32 = 180;
    let mut pixmap = tiny_skia::Pixmap::new(size, size).expect("failed to allocate pixmap");
    let svg_size = tree.size();
    let scale = size as f32 / svg_size.width().max(svg_size.height());
    let transform = tiny_skia::Transform::from_scale(scale, scale);
    resvg::render(&tree, transform, &mut pixmap.as_mut());

    let png = pixmap.encode_png().expect("failed to encode PNG");
    fs::write(out_dir.join("apple-touch-icon.png"), png)
        .expect("failed to write apple-touch-icon.png");
}

fn get_git_version() -> String {
    if let Ok(version) = std::env::var("GIT_VERSION")
        && !version.is_empty()
        && version != "dev"
    {
        return version;
    }

    Command::new("git")
        .args(["describe", "--tags", "--always", "--dirty"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map_or_else(
            || "dev".to_string(),
            |o| String::from_utf8_lossy(&o.stdout).trim().to_string(),
        )
}
