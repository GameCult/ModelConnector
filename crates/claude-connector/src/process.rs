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

    fn cvt(result: libc::c_int) -> io::Result<libc::c_int> {
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(result)
        }
    }

    /// Makes `source` also descriptor `target`, open across exec. Runs between
    /// fork and exec in the child, so it calls nothing but `dup2` and `fcntl`.
    fn place_fd(source: RawFd, target: RawFd) -> io::Result<()> {
        // SAFETY: dup2 and fcntl take integers only and are async-signal-safe.
        unsafe {
            if source == target {
                // dup2 onto itself changes nothing, so the close-on-exec flag
                // the pipe was created with must be cleared by hand.
                let flags = cvt(libc::fcntl(target, libc::F_GETFD))?;
                cvt(libc::fcntl(
                    target,
                    libc::F_SETFD,
                    flags & !libc::FD_CLOEXEC,
                ))?;
            } else {
                cvt(libc::dup2(source, target))?;
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
            // `place_fd` makes reaches the child.
            let (reader, mut writer) = std::io::pipe()?;
            writer.write_all(token.as_bytes())?;
            drop(writer);
            let source = reader.as_raw_fd();
            // SAFETY: the closure calls only async-signal-safe functions.
            unsafe { command.pre_exec(move || place_fd(source, TOKEN_FD)) };
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

    #[cfg(test)]
    mod tests {
        use super::*;

        fn cloexec(fd: RawFd) -> bool {
            // SAFETY: fcntl on an integer descriptor.
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            assert!(flags >= 0, "descriptor {fd} is not open");
            flags & libc::FD_CLOEXEC != 0
        }

        /// A descriptor at or above 300 on the same pipe, so a test never
        /// touches a low number another thread may be using.
        fn high_dup(source: RawFd, close_on_exec: bool) -> RawFd {
            let command = if close_on_exec {
                libc::F_DUPFD_CLOEXEC
            } else {
                libc::F_DUPFD
            };
            // SAFETY: fcntl on an integer descriptor.
            let fd = unsafe { libc::fcntl(source, command, 300) };
            assert!(fd >= 300);
            fd
        }

        fn close(fd: RawFd) {
            // SAFETY: closing a descriptor the test owns.
            unsafe { libc::close(fd) };
        }

        #[test]
        fn placing_a_descriptor_on_itself_clears_close_on_exec() {
            let (reader, _writer) = std::io::pipe().unwrap();
            let fd = high_dup(reader.as_raw_fd(), true);
            assert!(cloexec(fd));
            place_fd(fd, fd).unwrap();
            assert!(!cloexec(fd), "it must survive exec");
            // One that already survives is left alone, not refused.
            place_fd(fd, fd).unwrap();
            assert!(!cloexec(fd));
            close(fd);
        }

        #[test]
        fn placing_a_descriptor_elsewhere_copies_it_open_across_exec() {
            let (reader, _writer) = std::io::pipe().unwrap();
            let source = high_dup(reader.as_raw_fd(), true);
            let target = high_dup(reader.as_raw_fd(), true);
            assert!(cloexec(target));
            place_fd(source, target).unwrap();
            assert!(!cloexec(target), "the copy survives exec");
            assert!(cloexec(source), "the source does not");
            close(source);
            close(target);
        }

        #[test]
        fn a_descriptor_that_is_not_open_is_refused_either_way() {
            let (reader, _writer) = std::io::pipe().unwrap();
            let closed = high_dup(reader.as_raw_fd(), true);
            close(closed);
            assert!(place_fd(closed, closed).is_err());
            assert!(place_fd(closed, closed + 1).is_err());
        }
    }
}
