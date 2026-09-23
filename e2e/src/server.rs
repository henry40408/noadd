//! The noadd instances under test, each with its own `SQLite` file and HTTP +
//! DNS ports.
//!
//! Seeded suites boot, stop, seed, boot: noadd creates the schema on first
//! start and the fixture is written to the *stopped* database with `sqlite3`.
//! So [`Server::stop`] is a graceful SIGTERM (the WAL is checkpointed), and
//! [`Server::start`] can be called again on the same handle.
//!
//! The binary is spawned directly, not via `cargo run`, so the PID held is
//! noadd's own; killing `cargo` would leave the server holding the port.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::process::{Child, Command};

/// How long to wait for an instance to answer `/api/health`.
const STARTUP_TIMEOUT: Duration = Duration::from_secs(60);

/// How long a SIGTERM gets before the process is killed outright.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(10);

/// Recomputes the maintained `query_logs` row count after a seed (see
/// [`Server::seed`]). An upsert: the row exists only once noadd has migrated.
const RECOUNT_LOGS: &str = "INSERT INTO settings (key, value) \
     SELECT 'query_log_count', COUNT(*) FROM query_logs WHERE true \
     ON CONFLICT(key) DO UPDATE SET value = excluded.value;\n";

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
            // Inherited, so a refusal to start shows in the test output.
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .with_context(|| format!("spawning noadd at {}", binary.display()))?;

        // Stored before the wait, so a server that never answers is still killed.
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
            // `kill(2)` needs unsafe code (denied here) and `Child::kill` is
            // SIGKILL, which skips the checkpoint the seeding suites need.
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
    /// The instance must be stopped: fixtures rewrite settings noadd reads at
    /// boot. Rows written here bypass the maintained `query_logs` count in
    /// `settings`, so it is recomputed after every seed.
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
            .write_all(format!("{sql}\n{RECOUNT_LOGS}").as_bytes())
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

/// Where every instance's database lives (gitignored); [`Server::fresh`] wipes its own.
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

/// Path to the noadd binary: `NOADD_BIN`, else `target/debug/noadd`, built only
/// when missing. An existing binary is not rebuilt, so run `cargo build` first
/// or the embedded UI is stale.
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
