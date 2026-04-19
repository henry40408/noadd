use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const LISTS: &[(&str, &str)] = &[
    (
        "adguard_dns",
        "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt",
    ),
    ("easylist", "https://easylist.to/easylist/easylist.txt"),
    (
        "peter_lowe",
        "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext",
    ),
    ("oisd_small", "https://small.oisd.nl/"),
    (
        "steven_black",
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    ),
    ("urlhaus", "https://urlhaus.abuse.ch/downloads/hostfile/"),
];

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/index");

    let git_version = get_git_version();
    println!("cargo:rustc-env=GIT_VERSION={git_version}");

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR not set"));
    let out_lists_dir = out_dir.join("lists");
    fs::create_dir_all(&out_lists_dir).expect("failed to create output lists directory");

    for (name, url) in LISTS {
        let out_file = out_lists_dir.join(format!("{name}.txt"));

        if !download(url, &out_file) {
            eprintln!("cargo:warning=Download failed for {name}, using empty file");
            fs::write(&out_file, b"")
                .unwrap_or_else(|e| panic!("failed to write empty file for {name}: {e}"));
        }
    }

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
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "dev".to_string())
}

fn download(url: &str, dest: &Path) -> bool {
    let result = Command::new("curl")
        .args(["-sL", "--max-time", "30", url, "-o"])
        .arg(dest)
        .status();

    match result {
        Ok(status) => {
            status.success()
                && dest.exists()
                && fs::metadata(dest).map(|m| m.len() > 0).unwrap_or(false)
        }
        Err(_) => false,
    }
}
