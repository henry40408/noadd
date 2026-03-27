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
