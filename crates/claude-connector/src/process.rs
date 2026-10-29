//! The one OS seam: starting the child and reading its output.

use std::io;
use std::path::Path;
use std::time::Instant;

use crate::launch::ChildEnv;

/// What one read of the child's stdout produced.
#[derive(Debug, PartialEq, Eq)]
pub enum StdoutRead {
    /// One non-empty line, without its terminator.
    Line(Vec<u8>),
    /// The child closed its stdout.
    Eof,
    /// The deadline passed first.
    Timeout,
    /// A line or the total output passed its cap.
    Breach,
}

/// Starts a `claude` child. `argv[0]` is the program; the environment is
/// exactly `env`; `stdin` is written and closed. `token` is the child's
/// credential: it reaches the child on a pipe at `launch::TOKEN_FD`, once, and
/// is in no environment.
pub trait ProcessPort: Send + Sync {
    fn spawn(
        &self,
        argv: &[String],
        env: &ChildEnv,
        cwd: &Path,
        stdin: Vec<u8>,
        token: &str,
    ) -> io::Result<Box<dyn RunningChild>>;
}

/// A started child. The backend ends every child with `kill` then `wait`.
pub trait RunningChild: Send {
    fn read_line(&mut self, deadline: Instant) -> StdoutRead;
    /// The last bytes the child wrote to stderr.
    fn stderr_tail(&self) -> Vec<u8>;
    /// Kills the child and everything it started.
    fn kill(&mut self);
    fn wait(&mut self);
}

#[cfg(unix)]
pub use unix::StdProcessPort;

#[cfg(unix)]
mod unix {
    use std::io::{self, BufRead, BufReader, Read, Write};
    use std::os::fd::{AsRawFd, RawFd};
    use std::os::unix::process::CommandExt;
    use std::path::Path;
    use std::process::{Child, Command, Stdio};
    use std::sync::mpsc::{Receiver, RecvTimeoutError, channel};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::{Duration, Instant};

    use super::{ProcessPort, RunningChild, StdoutRead};
    use crate::config::ClaudeCodeLimits;
    use crate::launch::{ChildEnv, TOKEN_FD};

    /// A pipe holds a token without blocking the writer; a token is a few
    /// hundred bytes, so anything near the pipe's capacity is not one.
    const MAX_TOKEN_BYTES: usize = 4096;

    /// Puts the pipe's read end at [`TOKEN_FD`] in the child. Runs between
    /// fork and exec, so it calls nothing but `dup2` and `fcntl`.
    fn place_token_fd(source: RawFd) -> io::Result<()> {
        // SAFETY: dup2 and fcntl take integers only and are async-signal-safe.
        unsafe {
            if source == TOKEN_FD {
                // dup2 onto itself changes nothing, so the close-on-exec flag
                // the pipe was created with must be cleared by hand.
                let flags = libc::fcntl(TOKEN_FD, libc::F_GETFD);
                if flags < 0 || libc::fcntl(TOKEN_FD, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0
                {
                    return Err(io::Error::last_os_error());
                }
            } else if libc::dup2(source, TOKEN_FD) < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }

    /// Spawns each child in its own process group, so that killing the call
    /// kills what the child started too.
    pub struct StdProcessPort {
        limits: ClaudeCodeLimits,
    }

    impl StdProcessPort {
        pub fn new(limits: ClaudeCodeLimits) -> Self {
            Self { limits }
        }
    }

    impl ProcessPort for StdProcessPort {
        fn spawn(
            &self,
            argv: &[String],
            env: &ChildEnv,
            cwd: &Path,
            stdin: Vec<u8>,
            token: &str,
        ) -> io::Result<Box<dyn RunningChild>> {
            if token.len() > MAX_TOKEN_BYTES {
                return Err(io::Error::from(io::ErrorKind::InvalidInput));
            }
            let (program, args) = argv
                .split_first()
                .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
            let mut command = Command::new(program);
            command
                .args(args)
                .env_clear()
                .envs(env.iter())
                .current_dir(cwd)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .process_group(0);
            // The write end closes here, so the child sees the token and then
            // the end of the pipe. Both ends are close-on-exec; only the copy
            // `place_token_fd` makes reaches the child.
            let (reader, mut writer) = std::io::pipe()?;
            writer.write_all(token.as_bytes())?;
            drop(writer);
            let source = reader.as_raw_fd();
            // SAFETY: the closure calls only async-signal-safe functions.
            unsafe { command.pre_exec(move || place_token_fd(source)) };
            let mut child = command.spawn()?;
            drop(reader);
            let (stdin_pipe, stdout, stderr) =
                (child.stdin.take(), child.stdout.take(), child.stderr.take());

            if let Some(mut pipe) = stdin_pipe {
                thread::spawn(move || {
                    let _ = pipe.write_all(&stdin);
                });
            }

            let (lines, receiver) = channel();
            if let Some(stdout) = stdout {
                let limits = self.limits;
                thread::spawn(move || {
                    let mut reader = BufReader::new(stdout);
                    let mut total = 0usize;
                    loop {
                        let mut line = Vec::new();
                        let read = reader
                            .by_ref()
                            .take(limits.max_line_bytes as u64 + 1)
                            .read_until(b'\n', &mut line);
                        let Ok(read) = read else { break };
                        if read == 0 {
                            break;
                        }
                        total = total.saturating_add(read);
                        let terminated = line.last() == Some(&b'\n');
                        if terminated {
                            line.pop();
                        }
                        if line.last() == Some(&b'\r') {
                            line.pop();
                        }
                        if line.len() > limits.max_line_bytes || total > limits.max_total_bytes {
                            let _ = lines.send(Piece::Breach);
                            return;
                        }
                        if !line.is_empty() && lines.send(Piece::Line(line)).is_err() {
                            return;
                        }
                    }
                });
            }

            let tail = Arc::new(Mutex::new(Vec::new()));
            let stderr_reader = stderr.map(|mut stderr| {
                let (tail, keep) = (tail.clone(), self.limits.stderr_tail_bytes);
                thread::spawn(move || {
                    let mut chunk = [0u8; 4096];
                    while let Ok(read) = stderr.read(&mut chunk) {
                        if read == 0 {
                            break;
                        }
                        let mut held = tail.lock().unwrap_or_else(|e| e.into_inner());
                        held.extend_from_slice(&chunk[..read]);
                        let excess = held.len().saturating_sub(keep);
                        held.drain(..excess);
                    }
                })
            });

            Ok(Box::new(StdChild {
                child,
                receiver,
                tail,
                stderr_reader,
                reaped: false,
            }))
        }
    }

    enum Piece {
        Line(Vec<u8>),
        Breach,
    }

    struct StdChild {
        child: Child,
        receiver: Receiver<Piece>,
        tail: Arc<Mutex<Vec<u8>>>,
        stderr_reader: Option<thread::JoinHandle<()>>,
        reaped: bool,
    }

    impl RunningChild for StdChild {
        fn read_line(&mut self, deadline: Instant) -> StdoutRead {
            match self
                .receiver
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            {
                Ok(Piece::Line(line)) => StdoutRead::Line(line),
                Ok(Piece::Breach) => StdoutRead::Breach,
                Err(RecvTimeoutError::Timeout) => StdoutRead::Timeout,
                Err(RecvTimeoutError::Disconnected) => StdoutRead::Eof,
            }
        }

        fn stderr_tail(&self) -> Vec<u8> {
            self.tail.lock().unwrap_or_else(|e| e.into_inner()).clone()
        }

        fn kill(&mut self) {
            // The group leader stays a zombie until `wait`, so its pid is
            // still ours to signal.
            if !self.reaped {
                // SAFETY: killpg takes a process group id and no pointers.
                unsafe {
                    libc::killpg(self.child.id() as libc::pid_t, libc::SIGKILL);
                }
            }
        }

        fn wait(&mut self) {
            let _ = self.child.wait();
            self.reaped = true;
            // Every writer to stderr died with the group, so the tail is
            // complete once its reader sees the end. A process that escaped
            // the group is not waited for.
            if let Some(reader) = self.stderr_reader.take() {
                for _ in 0..100 {
                    if reader.is_finished() {
                        let _ = reader.join();
                        break;
                    }
                    thread::sleep(Duration::from_millis(2));
                }
            }
        }
    }

    impl Drop for StdChild {
        fn drop(&mut self) {
            self.kill();
            self.wait();
        }
    }
}
