//! The claude-connector binary.
//!
//!   claude-connector serve --config PATH.cc
//!   claude-connector config init PATH.cc --flag value ...
//!   claude-connector config add-caller PATH.cc --caller-id ID --connection-key-file F ...
//!   claude-connector config add-lease-caller PATH.cc --lease-user U --caller-id ID ...
//!   claude-connector config check PATH.cc
//!
//! `serve` takes its configuration from the typed document alone. The flags of
//! `config init` exist only to author that document. No message here echoes a
//! value that was typed or stored; refusals name a field or a flag.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::ExitCode;

use claude_connector::{
    ClaudeConnectorConfig, ConfigError, LeaseCallerConfig, MIN_SECRET_BYTES, check_ready,
    load_config, write_config,
};
use model_connector::{CallerConfig, LeaseTurn, ModelPrice, Rates, frame_bytes_for_payload};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let result = match args.as_slice() {
        ["serve", "--config", path] => serve(path),
        ["config", "init", path, flags @ ..] => init(path, flags),
        ["config", "add-caller", path, flags @ ..] => add_caller(path, flags),
        ["config", "add-lease-caller", path, flags @ ..] => add_lease_caller(path, flags),
        ["config", "check", path] => check(path),
        _ => Err(Failure::Usage),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(failure) => {
            eprintln!("claude-connector: {failure}");
            ExitCode::FAILURE
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum Failure {
    #[error(
        "usage: serve --config PATH | config init PATH --flag value ... | config add-caller PATH --flag value ... | config add-lease-caller PATH --flag value ... | config check PATH (check reads the credentials from the environment it runs in: run it in the unit's environment)"
    )]
    Usage,
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("flag {0} is missing")]
    Missing(&'static str),
    #[error("flag {0} is malformed")]
    Malformed(&'static str),
    #[error("a flag is unknown, repeated or has no value")]
    Flags,
}

#[cfg(unix)]
fn serve(path: &str) -> Result<(), Failure> {
    Ok(claude_connector::serve_config(path.as_ref())?)
}

#[cfg(not(unix))]
fn serve(_: &str) -> Result<(), Failure> {
    Err(Failure::Usage)
}

fn check(path: &str) -> Result<(), Failure> {
    let config = load_config(path.as_ref())?;
    check_ready(&config)?;
    println!("claude connector configuration is valid and ready to serve");
    println!("callers: {}", config.callers.len());
    println!("lease_callers: {}", config.lease_callers.len());
    println!("prices: {}", config.prices.len());
    Ok(())
}

/// The flags of one config verb: each single flag at most once, each list
/// flag any number of times.
struct Flags {
    single: BTreeMap<&'static str, String>,
    lists: BTreeMap<&'static str, Vec<String>>,
}

/// The flags that describe one caller, shared by `config init` (which writes
/// the first caller) and `config add-caller`.
const CALLER: [&str; 7] = [
    "--caller-id",
    "--connection-key-file",
    "--connection-key-epoch",
    "--spend-ceiling-micro-usd",
    "--spend-window-ms",
    "--max-concurrent-requests",
    "--max-output-tokens",
];

const INIT: [&str; 22] = [
    "--listen",
    "--replay-store",
    "--claude-binary",
    "--claude-sha256",
    "--work-dir",
    "--config-dir",
    "--prompt-dir",
    "--instance",
    "--token-credential",
    "--handle-secret-credential",
    "--handle-secret-file",
    "--deadline-ms",
    "--max-line-bytes",
    "--max-total-bytes",
    "--stderr-tail-bytes",
    "--max-payload-bytes",
    "--socket-timeout-ms",
    "--lease-socket",
    "--lease-max-ms",
    "--turn",
    "--lease-unit-instance",
    "--lease-reservation-micro-usd",
];

const LEASE_CALLER: [&str; 4] = [
    "--caller-id",
    "--turn",
    "--lease-unit-instance",
    "--lease-reservation-micro-usd",
];

impl Flags {
    fn parse(
        args: &[&str],
        singles: &[&[&'static str]],
        lists: &[&'static str],
    ) -> Result<Self, Failure> {
        let mut flags = Flags {
            single: BTreeMap::new(),
            lists: BTreeMap::new(),
        };
        let mut args = args.iter();
        while let Some(&name) = args.next() {
            let Some(&value) = args.next() else {
                return Err(Failure::Flags);
            };
            if let Some(list) = lists.iter().find(|known| **known == name) {
                flags
                    .lists
                    .entry(*list)
                    .or_default()
                    .push(value.to_string());
                continue;
            }
            let Some(known) = singles
                .iter()
                .flat_map(|set| set.iter())
                .find(|k| **k == name)
            else {
                return Err(Failure::Flags);
            };
            if flags.single.insert(*known, value.to_string()).is_some() {
                return Err(Failure::Flags);
            }
        }
        Ok(flags)
    }

    fn list(&self, name: &'static str) -> &[String] {
        self.lists.get(name).map_or(&[], Vec::as_slice)
    }

    fn text(&self, name: &'static str) -> Result<String, Failure> {
        self.single.get(name).cloned().ok_or(Failure::Missing(name))
    }

    fn path(&self, name: &'static str) -> Result<PathBuf, Failure> {
        self.text(name).map(PathBuf::from)
    }

    fn number<T: std::str::FromStr>(&self, name: &'static str) -> Result<T, Failure> {
        self.text(name)?
            .parse()
            .map_err(|_| Failure::Malformed(name))
    }

    /// The kind of turn a leasing account serves: `self` or `persona`.
    fn turn(&self) -> Result<LeaseTurn, Failure> {
        match self.text("--turn")?.as_str() {
            "self" => Ok(LeaseTurn::SelfRun),
            "persona" => Ok(LeaseTurn::PersonaTurn),
            _ => Err(Failure::Malformed("--turn")),
        }
    }

    fn number_or<T: std::str::FromStr>(
        &self,
        name: &'static str,
        default: T,
    ) -> Result<T, Failure> {
        match self.single.get(name) {
            None => Ok(default),
            Some(text) => text.parse().map_err(|_| Failure::Malformed(name)),
        }
    }

    /// The caller these flags describe. Its payload bound comes from
    /// `--max-payload-bytes` when the verb takes one.
    fn caller(&self) -> Result<CallerConfig, Failure> {
        Ok(CallerConfig {
            caller_runtime_id: self.text("--caller-id")?,
            connection_key_file: self.path("--connection-key-file")?,
            connection_key_epoch: self.number("--connection-key-epoch")?,
            allowed_models: self.list("--allowed-model").to_vec(),
            max_concurrent_requests: self.number_or("--max-concurrent-requests", 4)?,
            max_payload_bytes: self.number_or("--max-payload-bytes", 1 << 20)?,
            max_output_tokens: self.number_or("--max-output-tokens", 32_768)?,
            spend_ceiling_micro_usd: self.number("--spend-ceiling-micro-usd")?,
            spend_window_ms: self.number("--spend-window-ms")?,
        })
    }
}

fn sha256(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 || !hex.is_ascii() {
        return None;
    }
    let mut digest = [0_u8; 32];
    for (byte, pair) in digest.iter_mut().zip(hex.as_bytes().chunks(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(digest)
}

/// MODEL:INPUT:OUTPUT:CACHE_WRITE:CACHE_READ:OVERHEAD, rates in micro-USD per
/// million tokens. The one cache-write rate prices both retentions.
fn price(text: &str) -> Option<(String, ModelPrice)> {
    let mut parts = text.split(':');
    let model = parts.next()?.to_string();
    let mut next = || parts.next()?.parse::<u64>().ok();
    let (input, output, cache_write, cache_read, overhead_tokens) =
        (next()?, next()?, next()?, next()?, next()?);
    if parts.next().is_some() {
        return None;
    }
    Some((
        model,
        ModelPrice {
            rates: Rates {
                input,
                cache_write_short: cache_write,
                cache_write_long: cache_write,
                cache_read,
                output,
            },
            long_context: None,
            overhead_tokens,
        },
    ))
}

/// Writes 32 random bytes as 64 hex characters, mode 0600, unless the file is
/// already there: the secret is never read back or shown, and a file that
/// exists is the secret handles already depend on, so it is kept as it is when
/// it is a regular file, mode 0600, owned by this user and at least
/// `MIN_SECRET_BYTES` long, and refused untouched otherwise.
#[cfg(unix)]
fn ensure_secret_file(path: &std::path::Path) -> Result<(), Failure> {
    use std::io::{Read, Write};
    use std::os::unix::fs::OpenOptionsExt;

    if !path.is_absolute() {
        return Err(Failure::Malformed("--handle-secret-file"));
    }
    let mut file = match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
    {
        Ok(file) => file,
        Err(_) => return existing_secret_is_usable(path),
    };
    let mut bytes = [0_u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut random| random.read_exact(&mut bytes))
        .map_err(|_| Failure::Malformed("--handle-secret-file"))?;
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    file.write_all(hex.as_bytes())
        .map_err(|_| Failure::Malformed("--handle-secret-file"))
}

/// An existing secret file is accepted only as the connector would use it: not
/// a link, a regular file, readable by no one else, ours and long enough.
#[cfg(unix)]
fn existing_secret_is_usable(path: &std::path::Path) -> Result<(), Failure> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|_| Failure::Malformed("--handle-secret-file"))?;
    // SAFETY: geteuid has no preconditions and cannot fail.
    let uid = unsafe { libc::geteuid() };
    if secret_file_usable(&metadata, uid) {
        Ok(())
    } else {
        Err(Failure::Malformed("--handle-secret-file"))
    }
}

#[cfg(unix)]
fn secret_file_usable(metadata: &std::fs::Metadata, uid: u32) -> bool {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    metadata.is_file()
        && metadata.permissions().mode() & 0o7777 == 0o600
        && metadata.uid() == uid
        && metadata.len() >= MIN_SECRET_BYTES as u64
}

#[cfg(not(unix))]
fn ensure_secret_file(_: &std::path::Path) -> Result<(), Failure> {
    Err(Failure::Usage)
}

fn init(path: &str, args: &[&str]) -> Result<(), Failure> {
    let flags = Flags::parse(
        args,
        &[&INIT, &CALLER],
        &["--allowed-model", "--price", "--lease-user"],
    )?;
    let first = flags.caller()?;
    let mut prices = BTreeMap::new();
    for text in flags.list("--price") {
        let (model, price) = price(text).ok_or(Failure::Malformed("--price"))?;
        if prices.insert(model, price).is_some() {
            return Err(Failure::Malformed("--price"));
        }
    }
    let lease_callers = flags
        .list("--lease-user")
        .iter()
        .map(|unix_user| {
            Ok(LeaseCallerConfig {
                unix_user: unix_user.clone(),
                caller_id: first.caller_runtime_id.clone(),
                turn: flags.turn()?,
                unit_instance: flags.text("--lease-unit-instance")?,
                reservation_micro_usd: flags.number("--lease-reservation-micro-usd")?,
            })
        })
        .collect::<Result<Vec<_>, Failure>>()?;
    let secret_file = flags.path("--handle-secret-file")?;
    let config = ClaudeConnectorConfig {
        listen: flags.text("--listen")?,
        replay_store: flags.path("--replay-store")?,
        claude_binary: flags.path("--claude-binary")?,
        claude_binary_sha256: sha256(&flags.text("--claude-sha256")?)
            .ok_or(Failure::Malformed("--claude-sha256"))?,
        work_dir: flags.path("--work-dir")?,
        config_dir: flags.path("--config-dir")?,
        prompt_dir: flags.path("--prompt-dir")?,
        instance: flags.text("--instance")?,
        token_credential: flags.text("--token-credential")?,
        deadline_ms: flags.number_or("--deadline-ms", 600_000)?,
        max_line_bytes: flags.number_or("--max-line-bytes", 4 << 20)?,
        max_total_bytes: flags.number_or("--max-total-bytes", 64 << 20)?,
        stderr_tail_bytes: flags.number_or("--stderr-tail-bytes", 8192)?,
        max_frame_bytes: frame_bytes_for_payload(first.max_payload_bytes),
        max_connections: first.max_concurrent_requests.max(8),
        socket_timeout_ms: flags.number_or("--socket-timeout-ms", 10_000)?,
        max_expiry_skew_ms: 300_000,
        callers: vec![first],
        prices,
        lease_socket: flags.single.get("--lease-socket").map(PathBuf::from),
        lease_callers,
        lease_max_ms: flags.number_or("--lease-max-ms", 3_600_000)?,
        handle_secret_credential: flags.text("--handle-secret-credential")?,
    };
    // Validate before the secret file exists: a refused document leaves nothing.
    config.validate()?;
    ensure_secret_file(&secret_file)?;
    write_config(path.as_ref(), &config)?;
    Ok(())
}

/// Appends one caller to an existing document. The serve limits grow to carry
/// it: the frame to its payload bound, the connections to every caller's slots.
fn add_caller(path: &str, args: &[&str]) -> Result<(), Failure> {
    let flags = Flags::parse(
        args,
        &[&CALLER, &["--max-payload-bytes"]],
        &["--allowed-model"],
    )?;
    let caller = flags.caller()?;
    let mut config = load_config(path.as_ref())?;
    config.max_frame_bytes = config
        .max_frame_bytes
        .max(frame_bytes_for_payload(caller.max_payload_bytes));
    config.callers.push(caller);
    let slots: usize = config
        .callers
        .iter()
        .map(|caller| caller.max_concurrent_requests)
        .sum();
    config.max_connections = config.max_connections.max(slots);
    write_config(path.as_ref(), &config)?;
    Ok(())
}

/// Appends one leasing account to an existing document that lends a token.
fn add_lease_caller(path: &str, args: &[&str]) -> Result<(), Failure> {
    let flags = Flags::parse(args, &[&LEASE_CALLER, &["--lease-user"]], &[])?;
    let mut config = load_config(path.as_ref())?;
    config.lease_callers.push(LeaseCallerConfig {
        unix_user: flags.text("--lease-user")?,
        caller_id: flags.text("--caller-id")?,
        turn: flags.turn()?,
        unit_instance: flags.text("--lease-unit-instance")?,
        reservation_micro_usd: flags.number("--lease-reservation-micro-usd")?,
    });
    write_config(path.as_ref(), &config)?;
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    use super::*;

    #[test]
    fn a_secret_file_owned_by_someone_else_is_not_usable() {
        let dir =
            std::env::temp_dir().join(format!("claude-connector-main-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("handle.secret");
        std::fs::write(&path, "k".repeat(64)).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let metadata = std::fs::symlink_metadata(&path).unwrap();
        let owner = metadata.uid();
        assert!(secret_file_usable(&metadata, owner));
        assert!(!secret_file_usable(&metadata, owner.wrapping_add(1)));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
