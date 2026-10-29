//! Which systemd unit invocation a process runs in, from the system's own
//! record: the process's cgroup says the unit, and the service manager says
//! that unit's current InvocationID. The lease listener asks this through the
//! `PeerUnits` port; the answer never comes from the peer.
//!
//! This is the one place the connector asks systemd anything. It runs
//! `systemctl show` for one read-only property of one unit and takes nothing
//! from the output but a 32-digit hex id.

use std::fs;
use std::io::Read;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::lease::{PeerUnit, PeerUnits};

/// Answers `PeerUnits` from `<proc>/<pid>/cgroup` and `systemctl show`.
pub struct SystemdUnits {
    proc_root: PathBuf,
    systemctl: PathBuf,
    /// How long the manager has to answer before the lease is refused.
    deadline: Duration,
}

impl SystemdUnits {
    /// The running system's `/proc` and `systemctl`.
    pub fn system() -> Self {
        Self {
            proc_root: PathBuf::from("/proc"),
            systemctl: PathBuf::from("/usr/bin/systemctl"),
            deadline: Duration::from_secs(5),
        }
    }

    /// The pid a process handle names now, from the handle's own record. The
    /// handle holds the process's identity, so the number cannot have been
    /// recycled; a process that has exited reads as `-1`.
    fn pid_of(&self, process: BorrowedFd<'_>) -> Option<u32> {
        let info = fs::read_to_string(
            self.proc_root
                .join("self/fdinfo")
                .join(process.as_raw_fd().to_string()),
        )
        .ok()?;
        info.lines()
            .find_map(|line| line.strip_prefix("Pid:"))?
            .trim()
            .parse()
            .ok()
    }

    fn unit_in_cgroup(&self, pid: u32) -> Option<String> {
        let cgroup = fs::read_to_string(self.proc_root.join(pid.to_string()).join("cgroup"));
        unit_of_cgroup(&cgroup.ok()?)
    }

    /// `systemctl show` of `unit`'s InvocationID, killed and refused if it has
    /// not exited by the deadline.
    fn invocation_of(&self, unit: &str) -> Option<String> {
        let mut child = Command::new(&self.systemctl)
            .env_clear()
            .args(["show", "--property=InvocationID", "--value", "--", unit])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        let give_up = Instant::now() + self.deadline;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if Instant::now() < give_up => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
            }
        };
        if !status.success() {
            return None;
        }
        // The id is 33 bytes; anything past a small bound is not an answer.
        let mut output = Vec::new();
        child
            .stdout
            .take()?
            .take(256)
            .read_to_end(&mut output)
            .ok()?;
        invocation_id_of(std::str::from_utf8(&output).ok()?)
    }
}

/// The service unit a cgroup file puts its process in: the last component of
/// the unified-hierarchy path, if it names a `.service`. A process in a
/// sub-cgroup, a scope, a slice or the root is in no service unit this
/// recognises.
pub fn unit_of_cgroup(cgroup: &str) -> Option<String> {
    let path = cgroup.lines().find_map(|line| line.strip_prefix("0::"))?;
    let unit = path.rsplit('/').next()?;
    (unit.len() > ".service".len() && unit.ends_with(".service")).then(|| unit.to_string())
}

/// An InvocationID as `systemctl show --value` prints it: 32 lowercase hex
/// digits and a newline. Anything else (including the empty answer of a unit
/// that is not running) is not an invocation.
pub fn invocation_id_of(output: &str) -> Option<String> {
    let id = output.strip_suffix('\n').unwrap_or(output);
    (id.len() == 32 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
        .then(|| id.to_string())
}

impl PeerUnits for SystemdUnits {
    fn invocation_in(&self, process: BorrowedFd<'_>, unit: &str) -> Option<PeerUnit> {
        let pid = self.pid_of(process)?;
        // A process in any other unit is not asked about.
        if self.unit_in_cgroup(pid).as_deref() != Some(unit) {
            return None;
        }
        let invocation_id = self.invocation_of(unit)?;
        // The same process must still be in that unit now: one that left (or
        // died) while the manager was asked is not vouched for.
        (self.pid_of(process) == Some(pid) && self.unit_in_cgroup(pid).as_deref() == Some(unit))
            .then(|| PeerUnit {
                unit: unit.to_string(),
                invocation_id,
            })
    }
}

#[cfg(test)]
mod tests {
    use std::os::fd::{AsFd, AsRawFd, OwnedFd};

    use super::*;

    #[test]
    fn a_service_unit_is_the_last_cgroup_component() {
        let service = "0::/system.slice/system-mind\\x2dself.slice/mind-self@huginn.service\n";
        assert_eq!(
            unit_of_cgroup(service).as_deref(),
            Some("mind-self@huginn.service")
        );
        // Several hierarchies listed: the unified one decides.
        let hybrid = "12:cpu:/foo\n0::/system.slice/mind-self@a.service\n";
        assert_eq!(
            unit_of_cgroup(hybrid).as_deref(),
            Some("mind-self@a.service")
        );
    }

    #[test]
    fn a_process_outside_a_service_unit_has_none() {
        for cgroup in [
            "0::/\n",
            "0::/user.slice/user-1000.slice/session-3.scope\n",
            "0::/user.slice/user-1000.slice/user@1000.service/app.slice/x.service/child\n",
            "0::/system.slice/mind-self@huginn.service/sub\n",
            "0::/system.slice/.service\n",
            "1:name=systemd:/system.slice/a.service\n",
            "",
        ] {
            assert_eq!(unit_of_cgroup(cgroup), None, "{cgroup:?}");
        }
    }

    #[test]
    fn an_invocation_id_is_exactly_32_lowercase_hex_digits() {
        let id = "0123456789abcdef0123456789abcdef";
        assert_eq!(invocation_id_of(&format!("{id}\n")).as_deref(), Some(id));
        assert_eq!(invocation_id_of(id).as_deref(), Some(id));
        for bad in [
            "",
            "\n",
            "0123456789ABCDEF0123456789ABCDEF\n",
            "0123456789abcdef0123456789abcde\n",
            "0123456789abcdef0123456789abcdef0\n",
            "0123456789abcdef0123456789abcdeg\n",
            "0123456789abcdef0123456789abcdef\n\n",
        ] {
            assert_eq!(invocation_id_of(bad), None, "{bad:?}");
        }
    }

    const ID: &str = "0123456789abcdef0123456789abcdef";
    const UNIT: &str = "mind-self@eureka.service";

    /// A fake `/proc` with one process in `cgroup`, and a fake `systemctl`
    /// that records its arguments, runs `side_effect`, and exits `status`
    /// after printing `output`.
    struct Fake {
        dir: PathBuf,
        units: SystemdUnits,
        // A script being written while another test forks is "text file
        // busy" when it is run: fakes take turns.
        _turn: std::sync::MutexGuard<'static, ()>,
    }

    static TURN: std::sync::Mutex<()> = std::sync::Mutex::new(());

    impl Fake {
        fn new(name: &str, cgroup: &str, output: &str, status: i32, side_effect: &str) -> Self {
            use std::os::unix::fs::PermissionsExt;
            let turn = TURN
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let dir = std::env::temp_dir().join(format!("unit-{}-{name}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            let side_effect = side_effect.replace("{d}", &dir.display().to_string());
            fs::create_dir_all(dir.join("proc/42")).unwrap();
            fs::write(dir.join("proc/42/cgroup"), cgroup).unwrap();
            let script = dir.join("systemctl");
            fs::write(
                &script,
                format!(
                    "#!/bin/sh\nprintf '%s' \"$*\" > {d}/args\n{side_effect}\nprintf '%s' '{output}'\nexit {status}\n",
                    d = dir.display()
                ),
            )
            .unwrap();
            fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
            let units = SystemdUnits {
                proc_root: dir.join("proc"),
                systemctl: script,
                deadline: Duration::from_secs(5),
            };
            Self {
                dir,
                units,
                _turn: turn,
            }
        }

        /// A process handle that names process `pid`, as the kernel's own
        /// record of the handle says (`-1` once the process has exited).
        fn process(&self, pid: i64) -> OwnedFd {
            let handle: OwnedFd = fs::File::open("/dev/null").unwrap().into();
            let info = self.dir.join("proc/self/fdinfo");
            fs::create_dir_all(&info).unwrap();
            fs::write(
                info.join(handle.as_raw_fd().to_string()),
                format!("pos:\t0\nflags:\t02000002\nPid:\t{pid}\nNSpid:\t{pid}\n"),
            )
            .unwrap();
            handle
        }

        fn invocation_in(&self, pid: i64, unit: &str) -> Option<PeerUnit> {
            self.units.invocation_in(self.process(pid).as_fd(), unit)
        }

        fn args(&self) -> String {
            fs::read_to_string(self.dir.join("args")).unwrap()
        }
    }

    impl Drop for Fake {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    fn eureka_cgroup() -> String {
        format!("0::/system.slice/{UNIT}\n")
    }

    #[test]
    fn a_process_in_the_unit_is_that_unit_at_the_invocation_the_manager_reports() {
        let fake = Fake::new("ok", &eureka_cgroup(), &format!("{ID}\n"), 0, "");
        assert_eq!(
            fake.invocation_in(42, UNIT),
            Some(PeerUnit {
                unit: UNIT.to_string(),
                invocation_id: ID.to_string()
            })
        );
        // The manager is asked for exactly the invocation of that unit.
        assert_eq!(
            fake.args(),
            format!("show --property=InvocationID --value -- {UNIT}")
        );
        // A handle on a process that has exited, or on one with no cgroup
        // record, is in no unit.
        assert_eq!(fake.invocation_in(-1, UNIT), None);
        assert_eq!(fake.invocation_in(43, UNIT), None);
    }

    #[test]
    fn a_process_outside_the_unit_is_not_asked_about() {
        let scope = Fake::new("scope", "0::/user.slice/session-3.scope\n", ID, 0, "");
        assert_eq!(scope.invocation_in(42, UNIT), None);
        assert!(!scope.dir.join("args").exists());
        drop(scope);
        // Another service, even a real one, is not the caller's unit: the
        // manager is never spawned for it.
        let other = Fake::new("other", "0::/system.slice/ssh.service\n", ID, 0, "");
        assert_eq!(other.invocation_in(42, UNIT), None);
        assert!(!other.dir.join("args").exists());
    }

    #[test]
    fn a_manager_that_fails_or_names_no_invocation_vouches_for_nothing() {
        let failed = Fake::new("fail", &eureka_cgroup(), ID, 1, "");
        assert_eq!(failed.invocation_in(42, UNIT), None);
        drop(failed);
        let not_running = Fake::new("idle", &eureka_cgroup(), "\n", 0, "");
        assert_eq!(not_running.invocation_in(42, UNIT), None);
        let missing = SystemdUnits {
            proc_root: not_running.dir.join("proc"),
            systemctl: not_running.dir.join("no-such-systemctl"),
            deadline: Duration::from_secs(5),
        };
        assert_eq!(
            missing.invocation_in(not_running.process(42).as_fd(), UNIT),
            None
        );
    }

    #[test]
    fn a_manager_that_does_not_answer_in_time_is_killed_and_the_lease_refused() {
        let mut fake = Fake::new("hung", &eureka_cgroup(), ID, 0, "exec sleep 30");
        fake.units.deadline = Duration::from_millis(200);
        let started = Instant::now();
        assert_eq!(fake.invocation_in(42, UNIT), None);
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn a_process_that_left_its_unit_while_the_manager_was_asked_is_not_vouched_for() {
        let fake = Fake::new(
            "moves",
            &eureka_cgroup(),
            ID,
            0,
            "printf '0::/system.slice/other.service\n' > {d}/proc/42/cgroup",
        );
        assert_eq!(fake.invocation_in(42, UNIT), None);
    }

    #[test]
    fn a_process_that_exited_while_the_manager_was_asked_is_not_vouched_for() {
        let fake = Fake::new("dies", &eureka_cgroup(), ID, 0, "");
        let handle = fake.process(42);
        let side = fake
            .dir
            .join("proc/self/fdinfo")
            .join(handle.as_raw_fd().to_string());
        let mut script = fs::read_to_string(fake.dir.join("systemctl")).unwrap();
        script = script.replace(
            "exit 0",
            &format!("printf 'Pid:\t-1\n' > {}\nexit 0", side.display()),
        );
        fs::write(fake.dir.join("systemctl"), script).unwrap();
        assert_eq!(fake.units.invocation_in(handle.as_fd(), UNIT), None);
    }
}
