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
    ("urlhaus", "https://urlhaus.abuse.ch/downloads/hostfile/"),
];

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

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
