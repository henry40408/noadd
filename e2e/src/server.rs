//! The noadd instances under test.
//!
//! Replaces `playwright.config.js`'s `webServer` block *and* the `startNoadd` /
//! `waitHealthy` / `stopNoadd` trio every spec file carried its own copy of.
//! Each instance gets its own `SQLite` file and its own HTTP + DNS ports, exactly
//! as before, and the port numbers are unchanged so nothing a developer has
//! bookmarked moves.
//!
//! Several suites need the boot–seed–boot dance: noadd creates the schema on
//! first start, the fixture is written against the *stopped* database with
//! `sqlite3`, and the second boot renders it. [`Server::stop`] is therefore a
//! real graceful stop (SIGTERM, so the WAL is checkpointed) rather than a kill,
//! and [`Server::start`] can be called again on the same handle.
//!
//! The binary is spawned directly rather than through `cargo run`, so the PID
//! held here is noadd's own. Killing `cargo` would leave the server it spawned
//! holding the port.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::process::{Child, Command};

/// How long to wait for an instance to answer `/api/health`.
const STARTUP_TIMEOUT: Duration = Duration::from_secs(60);

/// How long a SIGTERM gets before the process is killed outright.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(10);

/// A noadd instance: its ports, its database, and the process serving them.
#[derive(Debug)]
pub struct Server {
    http: u16,
    dns: u16,
    db: PathBuf,
    child: Option<Child>,
}

impl Server {
    /// Wipes the database and starts a fresh instance on the given ports.
    ///
    /// # Errors
    ///
    /// Fails when the binary is missing and cannot be built, when it cannot be
    /// spawned, or when it does not answer `/api/health` in time.
    pub async fn fresh(name: &str, http: u16, dns: u16) -> Result<Self> {
        let db = tmp_dir().join(format!("{name}.db"));
        tokio::fs::create_dir_all(tmp_dir()).await?;
        remove_db(&db).await?;
        let mut server = Self {
            http,
            dns,
            db,
            child: None,
        };
        server.start().await?;
        Ok(server)
    }

    /// Starts the process against the existing database.
    ///
    /// # Errors
    ///
    /// Fails when the binary cannot be spawned, or does not become healthy.
    pub async fn start(&mut self) -> Result<()> {
        if self.child.is_some() {
            return Ok(());
        }
        let binary = ensure_binary().await?;
        let child = Command::new(&binary)
            .args([
                "--db-path".as_ref(),
                self.db.as_os_str(),
                "--http-addr".as_ref(),
                format!("127.0.0.1:{}", self.http).as_ref(),
                "--dns-addr".as_ref(),
                format!("127.0.0.1:{}", self.dns).as_ref(),
                "--log-format".as_ref(),
                "json".as_ref(),
            ])
            .stdout(Stdio::null())
            // Inherited, so a refusal to start is visible in the test output
            // rather than swallowed into a pipe nobody reads.
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .with_context(|| format!("spawning noadd at {}", binary.display()))?;

        // Bound before the wait, so a server that never answers is still killed
        // when the error propagates.
        self.child = Some(child);
        self.wait_healthy().await
    }

    /// Stops the process, checkpointing the WAL on the way out.
    ///
    /// # Errors
    ///
    /// Never fails: a process that ignores SIGTERM is killed instead.
    pub async fn stop(&mut self) -> Result<()> {
        let Some(mut child) = self.child.take() else {
            return Ok(());
        };
        if let Some(pid) = child.id() {
            // `kill(2)` would mean unsafe code, which this workspace denies,
            // and `Child::kill` is SIGKILL — which skips the checkpoint the
            // seeding suites need.
            let _ = Command::new("kill")
                .args(["-TERM", &pid.to_string()])
                .status()
                .await;
        }
        if tokio::time::timeout(SHUTDOWN_GRACE, child.wait())
            .await
            .is_err()
        {
            let _ = child.kill().await;
        }
        Ok(())
    }

    /// Runs SQL against the stopped database with the `sqlite3` CLI.
    ///
    /// The instance must not be running: these fixtures backdate months of
    /// traffic and rewrite settings noadd reads at boot, so they are written
    /// between the two starts rather than underneath a live server.
    ///
    /// # Errors
    ///
    /// Fails when `sqlite3` is missing or exits non-zero.
    pub async fn seed(&self, sql: &str) -> Result<()> {
        use tokio::io::AsyncWriteExt as _;

        anyhow::ensure!(
            self.child.is_none(),
            "seed the database while the server is stopped: {} is still running",
            self.db.display()
        );
        let mut child = Command::new("sqlite3")
            .arg(&self.db)
            .stdin(Stdio::piped())
            // PRAGMA results would otherwise land in the test output.
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .context("running `sqlite3` — install it, or the seeded suites cannot run")?;
        child
            .stdin
            .as_mut()
            .context("sqlite3 stdin")?
            .write_all(sql.as_bytes())
            .await?;
        drop(child.stdin.take());
        let status = child.wait().await?;
        anyhow::ensure!(status.success(), "sqlite3 exited {status}");
        Ok(())
    }

    /// The origin every page object navigates against.
    pub fn base_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.http)
    }

    /// The UDP port the DNS listener answers on.
    pub fn dns_port(&self) -> u16 {
        self.dns
    }

    /// The `SQLite` file backing this instance.
    pub fn db_path(&self) -> &Path {
        &self.db
    }

    async fn wait_healthy(&self) -> Result<()> {
        let url = format!("{}/api/health", self.base_url());
        let client = reqwest::Client::new();
        let deadline = tokio::time::Instant::now() + STARTUP_TIMEOUT;
        while tokio::time::Instant::now() < deadline {
            if let Ok(res) = client.get(&url).send().await
                && res.status().is_success()
            {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        bail!("noadd did not answer {url} within {STARTUP_TIMEOUT:?}")
    }
}

/// Where every instance's database lives — gitignored, and wiped per run.
pub fn tmp_dir() -> PathBuf {
    crate_dir().join(".tmp")
}

async fn remove_db(db: &Path) -> Result<()> {
    for suffix in ["", "-wal", "-shm"] {
        let path = PathBuf::from(format!("{}{suffix}", db.display()));
        match tokio::fs::remove_file(&path).await {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("removing {}", path.display())),
        }
    }
    Ok(())
}

/// Path to the noadd binary, building it first when it is not there.
///
/// CI builds it in an earlier step, so this is the local-developer path — and
/// the reason it exists is that the admin UI is embedded at compile time, so a
/// suite run against a stale binary is testing yesterday's markup.
async fn ensure_binary() -> Result<PathBuf> {
    if let Ok(path) = std::env::var("NOADD_BIN") {
        return Ok(PathBuf::from(path));
    }
    let binary = repo_root().join("target/debug/noadd");
    if binary.is_file() {
        return Ok(binary);
    }

    eprintln!("e2e: {} is missing — building it", binary.display());
    let status = Command::new("cargo")
        .current_dir(repo_root())
        .arg("build")
        .status()
        .await
        .context("running `cargo build`")?;
    if !status.success() {
        bail!("`cargo build` failed with {status}");
    }
    if !binary.is_file() {
        bail!("`cargo build` did not produce {}", binary.display());
    }
    Ok(binary)
}

fn crate_dir() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

/// The repository root — the parent of this crate's directory.
pub fn repo_root() -> &'static Path {
    crate_dir().parent().expect("e2e/ always has a parent")
}
