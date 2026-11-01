//! `claude-connector serve --config` as a process: it binds, stays up, and
//! starts the usage poll beside the lease listener. Only a spawned binary
//! shows that `serve_config` calls the poll start at all; the poll's own
//! behaviour is tested against fake servers in `usage_poll`.
//!
//! The usage endpoint is a constant of the connector, so this test's poll
//! asks the real host with a made-up token and sees an answer or an
//! unreachable network; either way it logs a `usage poll:` state line, and
//! that line is what is asserted.
#![cfg(unix)]

use std::io::{BufRead, BufReader};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

const TOKEN: &str = "sk-ant-oat01-CANARY-must-never-surface";

struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        let dir =
            std::env::temp_dir().join(format!("claude-connector-serve-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Kills the served process however the test ends.
struct Served(Child);

impl Drop for Served {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn run(args: &[&str]) {
    let made = Command::new(env!("CARGO_BIN_EXE_claude-connector"))
        .args(args)
        .env_clear()
        .output()
        .unwrap();
    assert!(made.status.success(), "{made:?}");
}

/// A document the connector can serve: a pinned stand-in for the claude
/// binary, a 0700 prompt directory, and the unit's credentials directory.
fn ready_document(scratch: &Scratch) -> (PathBuf, PathBuf) {
    let path = |name: &str| scratch.path(name);
    let text = |name: &str| path(name).to_string_lossy().into_owned();
    std::fs::write(path("claude"), b"not a real claude binary").unwrap();
    let pin = hex(&Sha256::digest(b"not a real claude binary"));
    for dir in ["work", "home", "prompts", "credentials"] {
        std::fs::create_dir(path(dir)).unwrap();
    }
    std::fs::set_permissions(path("prompts"), std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::write(path("caller.key"), "k".repeat(48)).unwrap();
    std::fs::write(path("credentials/claude-token"), TOKEN).unwrap();
    let config = text("connector.cc");
    run(&[
        "config",
        "init",
        &config,
        "--listen",
        "127.0.0.1:0",
        "--replay-store",
        &text("replay.cc"),
        "--claude-binary",
        &text("claude"),
        "--claude-sha256",
        &pin,
        "--work-dir",
        &text("work"),
        "--config-dir",
        &text("home"),
        "--prompt-dir",
        &text("prompts"),
        "--instance",
        "persona-a",
        "--token-credential",
        "claude-token",
        "--handle-secret-credential",
        "claude-handle-secret",
        "--handle-secret-file",
        &text("credentials/claude-handle-secret"),
        "--caller-id",
        "persona-a-caller",
        "--connection-key-file",
        &text("caller.key"),
        "--connection-key-epoch",
        "1",
        "--allowed-model",
        "claude-haiku-5-5",
    ]);
    (path("connector.cc"), path("credentials"))
}

fn serve(config: &Path, credentials: &Path) -> (Served, mpsc::Receiver<String>) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_claude-connector"))
        .args(["serve", "--config"])
        .arg(config)
        .env_clear()
        .env("CREDENTIALS_DIRECTORY", credentials)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stderr = child.stderr.take().unwrap();
    let (lines, received) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            if lines.send(line).is_err() {
                return;
            }
        }
    });
    (Served(child), received)
}

#[test]
fn serve_config_starts_the_usage_poll_and_stays_up() {
    let scratch = Scratch::new();
    let (config, credentials) = ready_document(&scratch);
    let (mut served, lines) = serve(&config, &credentials);

    let deadline = Instant::now() + Duration::from_secs(60);
    let mut seen = Vec::new();
    let poll_line = loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match lines.recv_timeout(left) {
            Ok(line) if line.contains("usage poll:") => break line,
            Ok(line) => seen.push(line),
            Err(_) => panic!("no usage poll state line; the connector said {seen:?}"),
        }
    };
    assert!(
        served.0.try_wait().unwrap().is_none(),
        "the connector exited after starting the poll"
    );
    assert!(!poll_line.contains("CANARY"), "{poll_line}");
}
