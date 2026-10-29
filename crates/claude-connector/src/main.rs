//! The claude-connector binary.
//!
//!   claude-connector serve --config PATH.cc
//!   claude-connector config init PATH.cc --flag value ...
//!   claude-connector config check PATH.cc
//!
//! `serve` takes its configuration from the typed document alone. The flags of
//! `config init` exist only to author that document. No message here echoes a
//! value that was typed or stored; refusals name a field or a flag.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::ExitCode;

use claude_connector::{
    ClaudeConnectorConfig, ConfigError, check_ready, load_config, write_config,
};
use model_connector::{CallerConfig, ModelPrice, Rates, frame_bytes_for_payload};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    let result = match args.as_slice() {
        ["serve", "--config", path] => serve(path),
        ["config", "init", path, flags @ ..] => init(path, flags),
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
    #[error("usage: serve --config PATH | config init PATH --flag value ... | config check PATH")]
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
    println!("allowed_models: {}", config.callers[0].allowed_models.len());
    println!("prices: {}", config.prices.len());
    Ok(())
}

/// The flags of `config init`, each given at most once except the two lists.
struct Flags {
    single: BTreeMap<&'static str, String>,
    models: Vec<String>,
    prices: Vec<String>,
}

const SINGLE: [&str; 22] = [
    "--listen",
    "--replay-store",
    "--claude-binary",
    "--claude-sha256",
    "--work-dir",
    "--config-dir",
    "--prompt-dir",
    "--instance",
    "--token-credential",
    "--caller-id",
    "--connection-key-file",
    "--connection-key-epoch",
    "--spend-ceiling-micro-usd",
    "--spend-window-ms",
    "--deadline-ms",
    "--max-line-bytes",
    "--max-total-bytes",
    "--stderr-tail-bytes",
    "--max-concurrent-requests",
    "--max-payload-bytes",
    "--max-output-tokens",
    "--socket-timeout-ms",
];

impl Flags {
    fn parse(args: &[&str]) -> Result<Self, Failure> {
        let mut flags = Flags {
            single: BTreeMap::new(),
            models: Vec::new(),
            prices: Vec::new(),
        };
        let mut args = args.iter();
        while let Some(&name) = args.next() {
            let Some(&value) = args.next() else {
                return Err(Failure::Flags);
            };
            match name {
                "--allowed-model" => flags.models.push(value.to_string()),
                "--price" => flags.prices.push(value.to_string()),
                _ => {
                    let Some(known) = SINGLE.iter().find(|known| **known == name) else {
                        return Err(Failure::Flags);
                    };
                    if flags.single.insert(*known, value.to_string()).is_some() {
                        return Err(Failure::Flags);
                    }
                }
            }
        }
        Ok(flags)
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

fn init(path: &str, args: &[&str]) -> Result<(), Failure> {
    let flags = Flags::parse(args)?;
    let max_payload_bytes: usize = flags.number_or("--max-payload-bytes", 1 << 20)?;
    let max_concurrent_requests: usize = flags.number_or("--max-concurrent-requests", 4)?;
    let mut prices = BTreeMap::new();
    for text in &flags.prices {
        let (model, price) = price(text).ok_or(Failure::Malformed("--price"))?;
        if prices.insert(model, price).is_some() {
            return Err(Failure::Malformed("--price"));
        }
    }
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
        max_frame_bytes: frame_bytes_for_payload(max_payload_bytes),
        max_connections: max_concurrent_requests.max(8),
        socket_timeout_ms: flags.number_or("--socket-timeout-ms", 10_000)?,
        max_expiry_skew_ms: 300_000,
        callers: vec![CallerConfig {
            caller_runtime_id: flags.text("--caller-id")?,
            connection_key_file: flags.path("--connection-key-file")?,
            connection_key_epoch: flags.number("--connection-key-epoch")?,
            allowed_models: flags.models.clone(),
            max_concurrent_requests,
            max_payload_bytes,
            max_output_tokens: flags.number_or("--max-output-tokens", 32_768)?,
            spend_ceiling_micro_usd: flags.number("--spend-ceiling-micro-usd")?,
            spend_window_ms: flags.number("--spend-window-ms")?,
        }],
        prices,
    };
    write_config(path.as_ref(), &config)?;
    Ok(())
}
