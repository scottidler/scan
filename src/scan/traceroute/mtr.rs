//! One long-lived `mtr --raw` child per traced family, folded into an [`Accumulator`].
//!
//! The session owns the child and its reader task. Every `poll` reports what the family shows
//! right now: the accumulated route, a per-family failure (a network condition or a stall), or
//! that mtr itself is unusable here and the scanner has to fall back to `traceroute`.

use super::TracerouteData;
use super::accumulator::Accumulator;
use crate::scan::{Family, RouteError, classify_route_error, kill_on_drop_command};
use std::io;
use std::net::IpAddr;
use std::process::{ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};
use tokio::process::Command;
use tokio::sync::Notify;
use tokio::task::JoinHandle;

pub const MTR_PROGRAM: &str = "mtr";
/// mtr's own default is 10 cycles; this is about 11.5 days at one cycle per second, and the
/// session respawns when it runs out.
pub const MTR_CYCLE_LIMIT: u32 = 1_000_000;
pub const MTR_STARTUP_GRACE_SECS: u64 = 5;
pub const MTR_RESPAWN_SECS: u64 = 5;
pub const MTR_STALL_SECS: u64 = 10;
/// Environment variable mtr reads extra options from; removed so a user's defaults cannot change
/// the flags scan relies on.
pub const MTR_OPTIONS_ENV: &str = "MTR_OPTIONS";
/// Stderr lines kept per child; the first names the failure, the rest only feed classification.
const STDERR_LINES_KEPT: usize = 8;

/// How long a session waits on its child at each stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MtrTimings {
    /// The first scan of a session waits this long for a parseable line.
    pub startup_grace: Duration,
    /// Minimum wait between a child ending and the next spawn for that family.
    pub respawn: Duration,
    /// No stdout line for this long and the child is killed and respawned.
    pub stall: Duration,
}

impl Default for MtrTimings {
    fn default() -> Self {
        Self {
            startup_grace: Duration::from_secs(MTR_STARTUP_GRACE_SECS),
            respawn: Duration::from_secs(MTR_RESPAWN_SECS),
            stall: Duration::from_secs(MTR_STALL_SECS),
        }
    }
}

/// Arguments for one `mtr --raw` session to `target`: numeric, one family, `max_hops` deep.
pub fn mtr_args(target: IpAddr, max_hops: u8) -> Vec<String> {
    let family_flag = if target.is_ipv6() { "-6" } else { "-4" };
    vec![
        "--raw".to_string(),
        "-n".to_string(),
        family_flag.to_string(),
        "-m".to_string(),
        max_hops.to_string(),
        "-c".to_string(),
        MTR_CYCLE_LIMIT.to_string(),
        target.to_string(),
    ]
}

/// The command for one mtr child: killed on drop, `MTR_OPTIONS` removed, stdin closed.
pub fn mtr_command(program: &str, args: &[String]) -> Command {
    let mut command = kill_on_drop_command(program);
    command
        .args(args)
        .env_remove(MTR_OPTIONS_ENV)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

/// What one family shows on this scan.
#[derive(Debug, Clone)]
pub enum SessionPoll {
    /// The accumulated route; it may have no hops yet while the route is forming.
    Streaming(TracerouteData),
    /// This family failed (no route, unreachable, stalled); the session retries on its own.
    Failed(String),
    /// mtr cannot run here; the scanner falls back to `traceroute` with this reason.
    Unusable(String),
}

/// The network text a failed child's stderr reports, when it is a network condition rather than
/// a broken mtr: errno 101, 99 on IPv6, or 113.
pub fn network_failure(stderr: &str, family: Family) -> Option<String> {
    match classify_route_error(stderr, family) {
        route @ RouteError::NoRoute(_) => Some(route.to_string()),
        RouteError::Other(text) if text != stderr => Some(text),
        RouteError::Other(_) => None,
    }
}

/// The fallback reason for a child that exited without one parseable line.
pub fn exit_reason(stderr_lines: &[String], status: Option<ExitStatus>) -> String {
    if let Some(first) = stderr_lines.first() {
        return format!("mtr: {first}");
    }
    match status.and_then(|status| status.code()) {
        Some(code) => format!("mtr exited {code}"),
        None => match status {
            Some(status) => format!("mtr exited ({status})"),
            None => "mtr exited".to_string(),
        },
    }
}

fn display_duration(duration: Duration) -> String {
    if duration.subsec_millis() == 0 {
        format!("{}s", duration.as_secs())
    } else {
        format!("{}ms", duration.as_millis())
    }
}

/// What one child has done so far, written by its reader task.
#[derive(Debug)]
struct RunProgress {
    parsed: bool,
    last_line: Instant,
    stderr: Vec<String>,
    /// Set once stdout and stderr are closed and the child is reaped.
    finished: Option<Option<ExitStatus>>,
}

/// One mtr child. Dropping it aborts the reader task, which drops the child, which kills it.
#[derive(Debug)]
struct MtrRun {
    started: Instant,
    progress: Arc<Mutex<RunProgress>>,
    changed: Arc<Notify>,
    task: JoinHandle<()>,
}

impl Drop for MtrRun {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl MtrRun {
    /// Wait until the child prints a parseable line or ends, at most until `deadline`.
    async fn wait_for_first_line(&self, deadline: Instant) {
        loop {
            {
                let progress = self.progress.lock().expect("mtr progress lock");
                if progress.parsed || progress.finished.is_some() {
                    return;
                }
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() || tokio::time::timeout(remaining, self.changed.notified()).await.is_err() {
                return;
            }
        }
    }
}

async fn read_stdout(
    stdout: impl AsyncRead + Unpin,
    accumulator: &Mutex<Accumulator>,
    progress: &Mutex<RunProgress>,
    changed: &Notify,
) {
    let mut reader = BufReader::new(stdout);
    let mut buffer = Vec::new();
    loop {
        buffer.clear();
        match reader.read_until(b'\n', &mut buffer).await {
            Ok(0) => return,
            Ok(_) => {
                let line = String::from_utf8_lossy(&buffer);
                let parsed = accumulator
                    .lock()
                    .expect("mtr accumulator lock")
                    .apply_line(line.trim_end());
                let mut progress = progress.lock().expect("mtr progress lock");
                progress.last_line = Instant::now();
                if parsed && !progress.parsed {
                    progress.parsed = true;
                    changed.notify_one();
                }
            }
            Err(e) => {
                log::warn!("[scan::traceroute::mtr] stdout_read_failed: error={e}");
                return;
            }
        }
    }
}

async fn read_stderr(stderr: impl AsyncRead + Unpin, progress: &Mutex<RunProgress>) {
    let mut lines = BufReader::new(stderr).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }
        log::debug!("[scan::traceroute::mtr] stderr: line={line:?}");
        let mut progress = progress.lock().expect("mtr progress lock");
        if progress.stderr.len() < STDERR_LINES_KEPT {
            progress.stderr.push(line);
        }
    }
}

/// One family's mtr stream: the accumulated counters outlive any one child.
#[derive(Debug)]
pub struct MtrSession {
    family: Family,
    target_ip: IpAddr,
    program: String,
    max_hops: u8,
    timings: MtrTimings,
    started: Instant,
    accumulator: Arc<Mutex<Accumulator>>,
    run: Option<MtrRun>,
    /// No spawn before this instant; set when a child ends or is killed.
    retry_at: Option<Instant>,
    spawned_any: bool,
    parsed_any: bool,
    failure: Option<String>,
}

impl MtrSession {
    /// A session for `target_ip`; the first `poll` spawns the child.
    pub fn new(program: impl Into<String>, target_ip: IpAddr, max_hops: u8, timings: MtrTimings) -> Self {
        let program = program.into();
        log::debug!(
            "[scan::traceroute::mtr] new: program={program} target={target_ip} max_hops={max_hops} timings={timings:?}"
        );
        Self {
            family: Family::of_ip(target_ip),
            target_ip,
            program,
            max_hops,
            timings,
            started: Instant::now(),
            accumulator: Arc::new(Mutex::new(Accumulator::new())),
            run: None,
            retry_at: None,
            spawned_any: false,
            parsed_any: false,
            failure: None,
        }
    }

    pub fn family(&self) -> Family {
        self.family
    }

    fn spawn(&mut self) -> io::Result<MtrRun> {
        let args = mtr_args(self.target_ip, self.max_hops);
        log::debug!(
            "[scan::traceroute::mtr] spawn: family={} program={} args={:?} respawn={}",
            self.family,
            self.program,
            args,
            self.spawned_any
        );
        let mut child = mtr_command(&self.program, &args).spawn()?;
        if self.spawned_any {
            self.accumulator.lock().expect("mtr accumulator lock").forget_seqs();
        }
        self.spawned_any = true;

        let stdout = child.stdout.take().expect("mtr stdout is piped");
        let stderr = child.stderr.take().expect("mtr stderr is piped");
        let started = Instant::now();
        let progress = Arc::new(Mutex::new(RunProgress {
            parsed: false,
            last_line: started,
            stderr: Vec::new(),
            finished: None,
        }));
        let changed = Arc::new(Notify::new());
        let task = {
            let accumulator = self.accumulator.clone();
            let progress = progress.clone();
            let changed = changed.clone();
            let family = self.family;
            tokio::spawn(async move {
                tokio::join!(
                    read_stdout(stdout, &accumulator, &progress, &changed),
                    read_stderr(stderr, &progress)
                );
                let status = match child.wait().await {
                    Ok(status) => Some(status),
                    Err(e) => {
                        log::warn!("[scan::traceroute::mtr] wait_failed: family={family} error={e}");
                        None
                    }
                };
                log::debug!("[scan::traceroute::mtr] child_ended: family={family} status={status:?}");
                progress.lock().expect("mtr progress lock").finished = Some(status);
                changed.notify_one();
            })
        };
        Ok(MtrRun {
            started,
            progress,
            changed,
            task,
        })
    }

    /// Note the child's end (or kill it) and hold off the next spawn for `timings.respawn`.
    fn end_run(&mut self) {
        self.run = None;
        self.retry_at = Some(Instant::now() + self.timings.respawn);
    }

    /// Spawn when due, wait out the startup grace on a session that has never parsed a line,
    /// then judge the child against the failure table.
    pub async fn poll(&mut self) -> SessionPoll {
        if self.run.is_none() && self.retry_at.is_none_or(|retry_at| Instant::now() >= retry_at) {
            match self.spawn() {
                Ok(run) => self.run = Some(run),
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    log::warn!("[scan::traceroute::mtr] not_installed: program={}", self.program);
                    return SessionPoll::Unusable("mtr not installed".to_string());
                }
                Err(e) => {
                    log::warn!(
                        "[scan::traceroute::mtr] spawn_failed: program={} error={e}",
                        self.program
                    );
                    return SessionPoll::Unusable(format!("mtr: {e}"));
                }
            }
        }

        if let Some(run) = &self.run
            && !self.parsed_any
        {
            run.wait_for_first_line(run.started + self.timings.startup_grace).await;
        }

        if let Some(run) = &self.run {
            let (parsed, last_line, stderr, finished) = {
                let progress = run.progress.lock().expect("mtr progress lock");
                (
                    progress.parsed,
                    progress.last_line,
                    progress.stderr.clone(),
                    progress.finished,
                )
            };
            let run_age = run.started.elapsed();
            self.parsed_any |= parsed;

            if let Some(status) = finished {
                self.end_run();
                if parsed {
                    log::info!(
                        "[scan::traceroute::mtr] child_exited_after_output: family={} status={status:?} respawn_in={}ms",
                        self.family,
                        self.timings.respawn.as_millis()
                    );
                } else if let Some(text) = network_failure(&stderr.join("\n"), self.family) {
                    log::warn!(
                        "[scan::traceroute::mtr] network_failure: family={} failure={text} retry_in={}ms",
                        self.family,
                        self.timings.respawn.as_millis()
                    );
                    self.failure = Some(text);
                } else {
                    let reason = exit_reason(&stderr, status);
                    log::warn!(
                        "[scan::traceroute::mtr] unusable: family={} reason={reason}",
                        self.family
                    );
                    return SessionPoll::Unusable(reason);
                }
            } else if !self.parsed_any && run_age >= self.timings.startup_grace {
                log::warn!(
                    "[scan::traceroute::mtr] no_output: family={} grace={}ms",
                    self.family,
                    self.timings.startup_grace.as_millis()
                );
                return SessionPoll::Unusable("mtr: no output".to_string());
            } else if last_line.elapsed() >= self.timings.stall {
                let text = format!("mtr stalled: no output for {}", display_duration(self.timings.stall));
                log::warn!("[scan::traceroute::mtr] stalled: family={} failure={text}", self.family);
                self.end_run();
                self.failure = Some(text);
            } else if parsed {
                self.failure = None;
            }
        }

        match &self.failure {
            Some(text) => SessionPoll::Failed(text.clone()),
            None => SessionPoll::Streaming(self.snapshot()),
        }
    }

    fn snapshot(&self) -> TracerouteData {
        self.accumulator.lock().expect("mtr accumulator lock").snapshot(
            self.target_ip,
            self.target_ip.is_ipv6(),
            self.max_hops,
            self.started.elapsed(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::testing::{temp_dir, write_executable_script};
    use std::path::PathBuf;

    fn v4() -> IpAddr {
        "192.0.2.1".parse().unwrap()
    }

    fn fast() -> MtrTimings {
        MtrTimings {
            startup_grace: Duration::from_millis(300),
            respawn: Duration::from_millis(50),
            stall: Duration::from_millis(300),
        }
    }

    /// A fake mtr running `body`; returns the dir (for cleanup) and the program path.
    fn fake_mtr(name: &str, body: &str) -> (PathBuf, String) {
        let dir = temp_dir(name);
        let script = dir.join("fake-mtr");
        write_executable_script(&script, &format!("#!/bin/sh\n{body}\n"));
        let program = script.to_string_lossy().into_owned();
        (dir, program)
    }

    #[test]
    fn args_are_raw_numeric_one_family_with_the_cycle_limit() {
        assert_eq!(
            mtr_args(v4(), 30),
            ["--raw", "-n", "-4", "-m", "30", "-c", "1000000", "192.0.2.1"]
        );
        let v6 = mtr_args("2001:db8::1".parse().unwrap(), 30);
        assert_eq!(v6[2], "-6");
        assert_eq!(v6.last().unwrap(), "2001:db8::1");
    }

    #[test]
    fn command_strips_mtr_options_and_kills_on_drop() {
        let command = mtr_command("mtr", &mtr_args(v4(), 30));
        assert!(command.get_kill_on_drop());
        let envs: Vec<_> = command.as_std().get_envs().collect();
        assert!(
            envs.contains(&(std::ffi::OsStr::new(MTR_OPTIONS_ENV), None)),
            "{envs:?}"
        );
    }

    #[test]
    fn network_failure_keeps_route_errors_and_rejects_the_rest() {
        assert_eq!(
            network_failure(
                "mtr: udp socket connect failed: Cannot assign requested address",
                Family::Ipv6
            ),
            Some("no IPv6 route on this host".to_string())
        );
        assert_eq!(
            network_failure("mtr: connect: Network is unreachable", Family::Ipv4),
            Some("no IPv4 route on this host".to_string())
        );
        assert_eq!(
            network_failure("mtr: No route to host", Family::Ipv4),
            Some("host unreachable".to_string())
        );
        assert_eq!(
            network_failure(
                "mtr: udp socket connect failed: Cannot assign requested address",
                Family::Ipv4
            ),
            None,
            "errno 99 on IPv4 is not a missing route"
        );
        assert_eq!(network_failure("mtr: Failure to open sockets", Family::Ipv4), None);
        assert_eq!(network_failure("", Family::Ipv4), None);
    }

    #[test]
    fn exit_reason_prefers_the_first_stderr_line_then_the_exit_code() {
        use std::os::unix::process::ExitStatusExt;
        let lines = vec!["Failure to open sockets".to_string(), "second".to_string()];
        assert_eq!(
            exit_reason(&lines, Some(ExitStatus::from_raw(1 << 8))),
            "mtr: Failure to open sockets"
        );
        assert_eq!(exit_reason(&[], Some(ExitStatus::from_raw(3 << 8))), "mtr exited 3");
        assert_eq!(exit_reason(&[], None), "mtr exited");
    }

    #[test]
    fn durations_display_in_seconds_or_millis() {
        assert_eq!(display_duration(Duration::from_secs(10)), "10s");
        assert_eq!(display_duration(Duration::from_millis(300)), "300ms");
    }

    #[tokio::test]
    async fn first_poll_waits_for_the_first_line_and_streams() {
        let (dir, program) = fake_mtr(
            "mtr-stream",
            "echo 'x 0 33000'; echo 'h 0 192.0.2.1'; echo 'p 0 500 33000'; echo 'x 0 33001'; exec sleep 2",
        );
        let mut session = MtrSession::new(program, v4(), 30, fast());
        let mut data = None;
        for _ in 0..50 {
            match session.poll().await {
                SessionPoll::Streaming(snapshot) if !snapshot.hops.is_empty() => {
                    data = Some(snapshot);
                    break;
                }
                SessionPoll::Streaming(_) => tokio::time::sleep(Duration::from_millis(10)).await,
                other => panic!("expected a stream: {other:?}"),
            }
        }
        drop(session);
        std::fs::remove_dir_all(&dir).unwrap();
        let data = data.expect("hop 1 settled within 500ms");
        assert_eq!(data.hops[0].sent, 1);
        assert!(data.destination_reached);
        assert_eq!(data.engine, super::super::TraceEngine::Mtr { cycles: 2 });
    }

    #[tokio::test]
    async fn exit_without_output_is_unusable_with_the_first_stderr_line() {
        let (dir, program) = fake_mtr(
            "mtr-broken",
            "echo 'Failure to open sockets' >&2; echo more >&2; exit 1",
        );
        let poll = MtrSession::new(program, v4(), 30, fast()).poll().await;
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(
            matches!(&poll, SessionPoll::Unusable(reason) if reason == "mtr: Failure to open sockets"),
            "{poll:?}"
        );
    }

    #[tokio::test]
    async fn silent_exit_is_unusable_with_the_exit_code() {
        let (dir, program) = fake_mtr("mtr-silent-exit", "exit 3");
        let poll = MtrSession::new(program, v4(), 30, fast()).poll().await;
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(
            matches!(&poll, SessionPoll::Unusable(reason) if reason == "mtr exited 3"),
            "{poll:?}"
        );
    }

    #[tokio::test]
    async fn no_line_within_the_grace_is_unusable() {
        let (dir, program) = fake_mtr("mtr-mute", "echo 'not raw output'; exec sleep 2");
        let started = Instant::now();
        let poll = MtrSession::new(program, v4(), 30, fast()).poll().await;
        let waited = started.elapsed();
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(
            matches!(&poll, SessionPoll::Unusable(reason) if reason == "mtr: no output"),
            "{poll:?}"
        );
        assert!(waited >= fast().startup_grace, "waited {waited:?}");
    }

    #[tokio::test]
    async fn missing_program_is_not_installed() {
        let poll = MtrSession::new("/nonexistent/scan-test/mtr", v4(), 30, fast())
            .poll()
            .await;
        assert!(
            matches!(&poll, SessionPoll::Unusable(reason) if reason == "mtr not installed"),
            "{poll:?}"
        );
    }

    #[tokio::test]
    async fn a_stalled_child_fails_the_family_and_is_respawned() {
        let dir = temp_dir("mtr-stall");
        let starts = dir.join("starts");
        let script = dir.join("fake-mtr");
        write_executable_script(
            &script,
            &format!(
                "#!/bin/sh\necho start >> {}\necho 'x 0 33000'\nexec sleep 2\n",
                starts.display()
            ),
        );
        let mut session = MtrSession::new(script.to_string_lossy(), v4(), 30, fast());
        assert!(matches!(session.poll().await, SessionPoll::Streaming(_)));

        tokio::time::sleep(fast().stall + Duration::from_millis(50)).await;
        let stalled = session.poll().await;
        assert!(
            matches!(&stalled, SessionPoll::Failed(text) if text == "mtr stalled: no output for 300ms"),
            "{stalled:?}"
        );

        tokio::time::sleep(fast().respawn + Duration::from_millis(20)).await;
        session.poll().await;
        let mut started = 0;
        for _ in 0..50 {
            started = std::fs::read_to_string(&starts).unwrap_or_default().lines().count();
            if started == 2 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        drop(session);
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(started, 2, "the stalled child was replaced");
    }
}
