use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const LISTS: &[(&str, &str)] = &[
    (
        "adguard_dns",
        "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt",
    ),
    (
        "peter_lowe",
        "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext",
    ),
    (
        "steven_black",
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    ),
    (
        "urlhaus",
        "https://urlhaus.abuse.ch/downloads/hostfile/",
    ),
];

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=lists/");

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR not set"));
    let out_lists_dir = out_dir.join("lists");
    fs::create_dir_all(&out_lists_dir).expect("failed to create output lists directory");

    let fallback_dir = Path::new("lists");

    for (name, url) in LISTS {
        let out_file = out_lists_dir.join(format!("{name}.txt"));
        let fallback_file = fallback_dir.join(format!("{name}.txt"));

        // Try downloading with curl
        let downloaded = download(url, &out_file);

        if downloaded {
            // Update local fallback snapshot
            if let Ok(content) = fs::read(&out_file) {
                let _ = fs::write(&fallback_file, &content);
            }
        } else if fallback_file.exists() {
            // Use local fallback
            eprintln!("cargo:warning=Download failed for {name}, using local fallback");
            fs::copy(&fallback_file, &out_file)
                .unwrap_or_else(|e| panic!("failed to copy fallback for {name}: {e}"));
        } else {
            // No fallback available — write empty file
            eprintln!("cargo:warning=No list available for {name}, using empty file");
            fs::write(&out_file, b"")
                .unwrap_or_else(|e| panic!("failed to write empty file for {name}: {e}"));
        }
    }
}

fn download(url: &str, dest: &Path) -> bool {
    let result = Command::new("curl")
        .args(["-sL", "--max-time", "30", url, "-o"])
        .arg(dest)
        .status();

    match result {
        Ok(status) => status.success() && dest.exists() && fs::metadata(dest).map(|m| m.len() > 0).unwrap_or(false),
        Err(_) => false,
    }
}
