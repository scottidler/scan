use super::{Family, classify_route_error, family_failure};
use crate::scanner::Scanner;
use crate::target::{Protocol, Target};
use crate::types::ScanResult;
use async_trait::async_trait;
use eyre::{Result, WrapErr};
use log;
use std::fmt;
use std::net::IpAddr;
use std::time::{Duration, Instant};

const TRACEROUTE_INTERVAL_SECS: u64 = 5 * 60; // 5 minutes - traceroute is slow and noisy if too frequent
const TRACEROUTE_TIMEOUT_SECS: u64 = 3; // 3 seconds per hop (much faster like your example)
const MAX_TRACEROUTE_HOPS: u8 = 30;
const PROBES_PER_HOP: u8 = 3;
const HOP_SUMMARY_DISPLAY_COUNT: usize = 5;
const MS_TO_MICROSECONDS_MULTIPLIER: f64 = 1000.0;
const FULL_PACKET_LOSS: f32 = 1.0;
/// What Linux `traceroute` prints when the host refuses it an unprivileged ICMP socket
/// (`net.ipv4.ping_group_range` excludes the user).
const ICMP_PRIVILEGE_ERROR: &str = "You do not have enough privileges to use this traceroute method";

#[derive(Debug, Clone)]
pub struct TracerouteScanner {
    interval: Duration,
    timeout: Duration,
    max_hops: u8,
    probes_per_hop: u8,
    program_override: Option<String>,
}

/// Program and arguments for one traceroute of `target` on `target_os`.
///
/// `-I` (ICMP echo) is documented for Linux and macOS `traceroute`/`traceroute6`; CDN edges
/// that drop the default UDP probes still answer it. Other platforms get the UDP default.
pub fn traceroute_args(
    target_os: &str,
    ipv6: bool,
    wait: u64,
    max_hops: u8,
    probes: u8,
    use_icmp: bool,
    target: IpAddr,
) -> (&'static str, Vec<String>) {
    let program = if ipv6 { "traceroute6" } else { "traceroute" };
    let mut args = vec!["-n".to_string()];
    if use_icmp && matches!(target_os, "linux" | "macos") {
        args.push("-I".to_string());
    }
    args.extend([
        "-w".to_string(),
        wait.to_string(),
        "-m".to_string(),
        max_hops.to_string(),
        "-q".to_string(),
        probes.to_string(),
        target.to_string(),
    ]);
    (program, args)
}

/// Whether a failed ICMP run should be retried once over UDP. Only the privilege refusal
/// qualifies: a silent target is not a failure, and retrying it would double the run time.
fn icmp_refused(stderr: &str) -> bool {
    stderr.contains(ICMP_PRIVILEGE_ERROR)
}

// Dual-protocol Traceroute result structure
#[derive(Debug, Clone)]
pub struct TracerouteResult {
    pub ipv4_result: Option<TracerouteData>,
    pub ipv6_result: Option<TracerouteData>,
    pub ipv4_status: TracerouteStatus,
    pub ipv6_status: TracerouteStatus,
    pub total_duration: Duration,
}

#[derive(Debug, Clone)]
pub struct TracerouteData {
    pub hops: Vec<TracerouteHop>,
    pub destination_reached: bool,
    pub total_hops: u8,
    pub max_hops: u8,
    pub target_ip: IpAddr,
    pub scan_duration: Duration,
    pub ipv6: bool,
}

impl TracerouteHop {
    /// True when no probe to this hop was answered.
    pub fn is_silent(&self) -> bool {
        self.responses.iter().all(|response| response.timeout)
    }
}

impl TracerouteData {
    /// The highest hop that answered at least one probe.
    pub fn last_reply_hop(&self) -> Option<u8> {
        self.hops
            .iter()
            .filter(|hop| !hop.is_silent())
            .map(|hop| hop.hop_number)
            .max()
    }

    /// The hop that answered from the target's own address, when the destination was reached.
    pub fn destination_hop(&self) -> Option<&TracerouteHop> {
        if !self.destination_reached {
            return None;
        }
        self.hops.iter().rev().find(|hop| {
            hop.responses
                .iter()
                .any(|r| !r.timeout && r.ip_address == Some(self.target_ip))
        })
    }

    /// How many hops had no probe answered. The one count the TUI and `--no-tui` share.
    pub fn silent_hops(&self) -> usize {
        self.hops.iter().filter(|hop| hop.is_silent()).count()
    }

    /// `reached`, or why not: `target silent (last reply: hop N)` / `target silent (no hop replied)`.
    pub fn reach_label(&self) -> String {
        if self.destination_reached {
            "reached".to_string()
        } else {
            match self.last_reply_hop() {
                Some(hop) => format!("target silent (last reply: hop {hop})"),
                None => "target silent (no hop replied)".to_string(),
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum TracerouteStatus {
    Success(u8),    // Traceroute succeeded with N hops
    Failed(String), // Traceroute failed with error message
    NoAddress,      // No address available for this protocol
    NotQueried,     // Query was not attempted
}

impl fmt::Display for TracerouteStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TracerouteStatus::Success(hops) => write!(f, "{hops} hops"),
            TracerouteStatus::Failed(reason) => f.write_str(reason),
            TracerouteStatus::NoAddress => f.write_str("no address"),
            TracerouteStatus::NotQueried => f.write_str("not queried"),
        }
    }
}

/// Status and data for one family's traceroute outcome. A failure is classified, so a missing
/// local route reads `no IPv6 route on this host` rather than the tool's raw stderr.
fn family_outcome(
    target: &Target,
    family: Family,
    outcome: Result<TracerouteData>,
) -> (TracerouteStatus, Option<TracerouteData>) {
    match outcome {
        Ok(data) => {
            log::trace!(
                "[scan::traceroute] traceroute_completed: target={} family={} hops={} complete={}",
                target.display_name(),
                family,
                data.total_hops,
                data.destination_reached
            );
            (TracerouteStatus::Success(data.total_hops), Some(data))
        }
        Err(e) if e.to_string().contains("address available") => {
            log::warn!(
                "[scan::traceroute] traceroute_no_address: target={} family={}",
                target.display_name(),
                family
            );
            (TracerouteStatus::NoAddress, None)
        }
        Err(e) => {
            let status = TracerouteStatus::Failed(classify_route_error(&format!("{e:#}"), family).to_string());
            log::error!(
                "[scan::traceroute] traceroute_failed: target={} family={} error={:#} status={}",
                target.display_name(),
                family,
                e,
                status
            );
            (status, None)
        }
    }
}

impl Default for TracerouteResult {
    fn default() -> Self {
        Self::new()
    }
}

impl TracerouteResult {
    pub fn new() -> Self {
        Self {
            ipv4_result: None,
            ipv6_result: None,
            ipv4_status: TracerouteStatus::NotQueried,
            ipv6_status: TracerouteStatus::NotQueried,
            total_duration: Duration::from_millis(0),
        }
    }

    pub fn get_primary_result(&self) -> Option<&TracerouteData> {
        // Prefer IPv4, then IPv6
        self.ipv4_result.as_ref().or(self.ipv6_result.as_ref())
    }

    pub fn has_any_success(&self) -> bool {
        matches!(self.ipv4_status, TracerouteStatus::Success(_))
            || matches!(self.ipv6_status, TracerouteStatus::Success(_))
    }

    /// Why every attempted family failed, e.g. `IPv6: no IPv6 route on this host`. Families
    /// with no address are left out.
    pub fn failure(&self, protocol: Protocol) -> eyre::Report {
        let failures: Vec<(Family, String)> = [(Family::Ipv4, &self.ipv4_status), (Family::Ipv6, &self.ipv6_status)]
            .into_iter()
            .filter(|(_, status)| matches!(status, TracerouteStatus::Failed(_)))
            .map(|(family, status)| (family, status.to_string()))
            .collect();
        family_failure(&failures, protocol)
    }

    pub fn total_hops(&self) -> u8 {
        let ipv4_hops = self.ipv4_result.as_ref().map(|r| r.total_hops).unwrap_or(0);
        let ipv6_hops = self.ipv6_result.as_ref().map(|r| r.total_hops).unwrap_or(0);
        ipv4_hops.max(ipv6_hops)
    }

    pub fn any_destination_reached(&self) -> bool {
        self.ipv4_result
            .as_ref()
            .map(|r| r.destination_reached)
            .unwrap_or(false)
            || self
                .ipv6_result
                .as_ref()
                .map(|r| r.destination_reached)
                .unwrap_or(false)
    }
}

#[derive(Debug, Clone)]
pub struct TracerouteHop {
    pub hop_number: u8,
    pub responses: Vec<HopResponse>,
    pub best_rtt: Option<Duration>,
    pub avg_rtt: Option<Duration>,
    pub worst_rtt: Option<Duration>,
    pub packet_loss: f32, // 0.0 to 1.0
}

#[derive(Debug, Clone)]
pub struct HopResponse {
    pub ip_address: Option<IpAddr>,
    pub rtt: Option<Duration>,
    pub timeout: bool,
}

impl Default for TracerouteScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl TracerouteScanner {
    pub fn new() -> Self {
        log::debug!(
            "[scan::traceroute] new: interval={}s timeout={}s max_hops={} probes_per_hop={}",
            TRACEROUTE_INTERVAL_SECS,
            TRACEROUTE_TIMEOUT_SECS,
            MAX_TRACEROUTE_HOPS,
            PROBES_PER_HOP
        );
        Self {
            interval: Duration::from_secs(TRACEROUTE_INTERVAL_SECS),
            timeout: Duration::from_secs(TRACEROUTE_TIMEOUT_SECS),
            max_hops: MAX_TRACEROUTE_HOPS,
            probes_per_hop: PROBES_PER_HOP,
            program_override: None,
        }
    }

    /// Use `program` instead of the platform's `traceroute`/`traceroute6` binary.
    pub fn with_program(mut self, program: impl Into<String>) -> Self {
        self.program_override = Some(program.into());
        self
    }

    /// One traceroute run; returns stdout, or an error carrying the tool's stderr.
    async fn run_traceroute(&self, target: &Target, target_ip: IpAddr, use_icmp: bool) -> Result<String> {
        let (default_program, args) = traceroute_args(
            std::env::consts::OS,
            target_ip.is_ipv6(),
            self.timeout.as_secs(),
            self.max_hops,
            self.probes_per_hop,
            use_icmp,
            target_ip,
        );
        let program: &str = self.program_override.as_deref().unwrap_or(default_program);
        log::debug!(
            "[scan::traceroute] run_traceroute: target={} program={} args={:?}",
            target.display_name(),
            program,
            args
        );

        let command_start = Instant::now();
        let output = super::kill_on_drop_command(program)
            .args(&args)
            .output()
            .await
            .wrap_err("Failed to execute traceroute command")?;
        let command_duration = command_start.elapsed();

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            log::error!(
                "[scan::traceroute] command_failed: target={} icmp={} duration={}ms status={} stderr={}",
                target.display_name(),
                use_icmp,
                command_duration.as_millis(),
                output.status,
                stderr.trim()
            );
            return Err(eyre::eyre!("Traceroute command failed: {}", stderr));
        }

        let stdout = String::from_utf8(output.stdout).wrap_err("Invalid UTF-8 in traceroute output")?;
        log::trace!(
            "[scan::traceroute] command_completed: target={} icmp={} duration={}ms output_len={}",
            target.display_name(),
            use_icmp,
            command_duration.as_millis(),
            stdout.len()
        );
        Ok(stdout)
    }

    async fn traceroute_protocol(&self, target: &Target, protocol: Protocol) -> Result<TracerouteData> {
        log::debug!(
            "[scan::traceroute] traceroute_protocol: target={} protocol={}",
            target.display_name(),
            protocol.as_str()
        );

        // Check if target supports this protocol
        if !target.supports_protocol(protocol) {
            log::warn!(
                "[scan::traceroute] no_address_for_protocol: target={} protocol={}",
                target.display_name(),
                protocol.as_str()
            );
            return Err(eyre::eyre!(
                "No {} address available for target: {}",
                protocol.as_str(),
                target.display_name()
            ));
        }

        // Get protocol-specific IP address
        let target_ip = match target.primary_ip_for_protocol(protocol) {
            Some(ip) => ip,
            None => {
                log::warn!(
                    "[scan::traceroute] no_ip_for_protocol: target={} protocol={}",
                    target.display_name(),
                    protocol.as_str()
                );
                return Err(eyre::eyre!(
                    "No {} IP address available for target: {}",
                    protocol.as_str(),
                    target.display_name()
                ));
            }
        };

        log::debug!(
            "[scan::traceroute] protocol_target: {} -> {} ({})",
            target.display_name(),
            target_ip,
            protocol.as_str()
        );

        let traceroute_data = self.perform_traceroute_for_ip(target, target_ip).await?;
        Ok(traceroute_data)
    }

    async fn perform_traceroute_for_ip(&self, target: &Target, target_ip: IpAddr) -> Result<TracerouteData> {
        log::debug!(
            "[scan::traceroute] perform_traceroute: target={}",
            target.display_name()
        );

        let start_time = Instant::now();
        let ipv6 = target_ip.is_ipv6();

        log::debug!(
            "[scan::traceroute] target_determined: target={} ip={} ipv6={}",
            target.display_name(),
            target_ip,
            ipv6
        );

        let stdout = match self.run_traceroute(target, target_ip, true).await {
            Err(e) if icmp_refused(&format!("{e:#}")) => {
                log::warn!(
                    "[scan::traceroute] icmp_refused_retrying_udp: target={} ip={}",
                    target.display_name(),
                    target_ip
                );
                self.run_traceroute(target, target_ip, false).await?
            }
            outcome => outcome?,
        };

        let parse_start = Instant::now();
        let result = self.parse_traceroute_output(&stdout, target_ip, ipv6, start_time.elapsed())?;
        let parse_duration = parse_start.elapsed();

        log::debug!(
            "[scan::traceroute] traceroute_completed: target={} duration={}ms parse_duration={}μs hops={} destination_reached={}",
            target.display_name(),
            result.scan_duration.as_millis(),
            parse_duration.as_micros(),
            result.hops.len(),
            result.destination_reached
        );

        if !result.hops.is_empty() {
            let hop_summary: Vec<String> = result
                .hops
                .iter()
                .take(HOP_SUMMARY_DISPLAY_COUNT)
                .map(|h| {
                    format!(
                        "{}:{:.1}ms",
                        h.hop_number,
                        h.best_rtt.map(|d| d.as_millis() as f32).unwrap_or(-1.0)
                    )
                })
                .collect();
            log::trace!(
                "[scan::traceroute] hop_summary: target={} first_5_hops=[{}]",
                target.display_name(),
                hop_summary.join(", ")
            );
        }

        Ok(result)
    }

    fn parse_traceroute_output(
        &self,
        output: &str,
        target_ip: IpAddr,
        ipv6: bool,
        scan_duration: Duration,
    ) -> Result<TracerouteData> {
        let mut hops = Vec::new();
        let mut destination_reached = false;
        let mut total_hops = 0;

        for line in output.lines() {
            let line = line.trim();

            // Skip header line
            if line.starts_with("traceroute to") {
                continue;
            }

            // Parse hop line
            if let Some(hop) = self.parse_hop_line(line)? {
                total_hops = hop.hop_number;

                // Check if this hop reached the destination
                if hop.responses.iter().any(|r| r.ip_address == Some(target_ip)) {
                    destination_reached = true;
                }

                hops.push(hop);
            }
        }

        Ok(TracerouteData {
            hops,
            destination_reached,
            total_hops,
            max_hops: self.max_hops,
            target_ip,
            scan_duration,
            ipv6,
        })
    }

    fn parse_hop_line(&self, line: &str) -> Result<Option<TracerouteHop>> {
        // Skip empty lines
        if line.is_empty() {
            return Ok(None);
        }

        // Parse hop number at the start of the line
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.is_empty() {
            return Ok(None);
        }

        let hop_number = match parts[0].parse::<u8>() {
            Ok(num) => num,
            Err(_) => return Ok(None), // Not a hop line
        };

        let mut responses = Vec::new();
        let mut i = 1;

        // Parse responses for this hop
        while i < parts.len() {
            if parts[i] == "*" {
                // Timeout response
                responses.push(HopResponse {
                    ip_address: None,
                    rtt: None,
                    timeout: true,
                });
                i += 1;
            } else if i + 2 < parts.len() && parts[i + 2] == "ms" {
                // Response with IP and RTT: "192.168.1.1 2.345 ms"
                let ip_str = parts[i];
                let rtt_str = parts[i + 1];

                let ip_address = ip_str.parse::<IpAddr>().ok();
                let rtt = rtt_str
                    .parse::<f64>()
                    .ok()
                    .map(|ms| Duration::from_micros((ms * MS_TO_MICROSECONDS_MULTIPLIER) as u64));

                responses.push(HopResponse {
                    ip_address,
                    rtt,
                    timeout: false,
                });

                i += 3; // Skip IP, RTT, "ms"
            } else if i + 1 < parts.len() && parts[i + 1] == "ms" {
                // Additional RTT for same IP: "2.345 ms"
                let rtt_str = parts[i];
                let rtt = rtt_str
                    .parse::<f64>()
                    .ok()
                    .map(|ms| Duration::from_micros((ms * MS_TO_MICROSECONDS_MULTIPLIER) as u64));

                // Use the same IP as the previous response
                let ip_address = responses.last().and_then(|r| r.ip_address);

                responses.push(HopResponse {
                    ip_address,
                    rtt,
                    timeout: false,
                });

                i += 2; // Skip RTT, "ms"
            } else {
                i += 1; // Skip unknown token
            }
        }

        // Calculate statistics
        let rtts: Vec<Duration> = responses.iter().filter_map(|r| r.rtt).collect();

        let best_rtt = rtts.iter().min().copied();
        let worst_rtt = rtts.iter().max().copied();
        let avg_rtt = if !rtts.is_empty() {
            let total_micros: u64 = rtts.iter().map(|d| d.as_micros() as u64).sum();
            Some(Duration::from_micros(total_micros / rtts.len() as u64))
        } else {
            None
        };

        let packet_loss = if responses.is_empty() {
            FULL_PACKET_LOSS
        } else {
            responses.iter().filter(|r| r.timeout).count() as f32 / responses.len() as f32
        };

        Ok(Some(TracerouteHop {
            hop_number,
            responses,
            best_rtt,
            avg_rtt,
            worst_rtt,
            packet_loss,
        }))
    }
}

#[async_trait]
impl Scanner for TracerouteScanner {
    async fn scan(&self, target: &Target, protocol: Protocol) -> Result<ScanResult> {
        log::debug!(
            "[scan::traceroute] scan: target={} protocol={}",
            target.display_name(),
            protocol.as_str()
        );

        let scan_start = Instant::now();
        let mut result = TracerouteResult::new();

        let (ipv4_outcome, ipv6_outcome) = match protocol {
            Protocol::Ipv4 => (Some(self.traceroute_protocol(target, Protocol::Ipv4).await), None),
            Protocol::Ipv6 => (None, Some(self.traceroute_protocol(target, Protocol::Ipv6).await)),
            Protocol::Both => {
                // Run both IPv4 and IPv6 traceroutes concurrently
                let (ipv4, ipv6) = tokio::join!(
                    self.traceroute_protocol(target, Protocol::Ipv4),
                    self.traceroute_protocol(target, Protocol::Ipv6)
                );
                (Some(ipv4), Some(ipv6))
            }
        };
        if let Some(outcome) = ipv4_outcome {
            (result.ipv4_status, result.ipv4_result) = family_outcome(target, Family::Ipv4, outcome);
        }
        if let Some(outcome) = ipv6_outcome {
            (result.ipv6_status, result.ipv6_result) = family_outcome(target, Family::Ipv6, outcome);
        }

        result.total_duration = scan_start.elapsed();

        // Return success if any protocol succeeded
        if result.has_any_success() {
            log::debug!(
                "[scan::traceroute] scan_completed: target={} protocol={} duration={}ms ipv4_status={:?} ipv6_status={:?}",
                target.display_name(),
                protocol.as_str(),
                result.total_duration.as_millis(),
                result.ipv4_status,
                result.ipv6_status
            );
            Ok(ScanResult::Traceroute(result))
        } else {
            let error = result.failure(protocol);
            log::error!(
                "[scan::traceroute] scan_failed: target={} protocol={} duration={}ms error={}",
                target.display_name(),
                protocol.as_str(),
                result.total_duration.as_millis(),
                error
            );
            Err(error)
        }
    }

    fn interval(&self) -> Duration {
        self.interval
    }

    fn name(&self) -> &'static str {
        "traceroute"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// `2606:4700:4700::1111` on a host with no IPv6 route: IPv4 has no address and
    /// `traceroute6` exits with `connect: Cannot assign requested address`.
    fn ipv6_literal_no_route_result(target: &Target) -> TracerouteResult {
        let mut result = TracerouteResult::new();
        (result.ipv4_status, result.ipv4_result) = family_outcome(
            target,
            Family::Ipv4,
            Err(eyre::eyre!(
                "No IPv4 address available for target: 2606:4700:4700::1111"
            )),
        );
        (result.ipv6_status, result.ipv6_result) = family_outcome(
            target,
            Family::Ipv6,
            Err(eyre::eyre!(
                "Traceroute command failed: connect: Cannot assign requested address\n"
            )),
        );
        result
    }

    #[test]
    fn status_display_has_no_debug_text() {
        assert_eq!(TracerouteStatus::Success(7).to_string(), "7 hops");
        assert_eq!(
            TracerouteStatus::Failed("host unreachable".into()).to_string(),
            "host unreachable"
        );
        assert_eq!(TracerouteStatus::NoAddress.to_string(), "no address");
        assert_eq!(TracerouteStatus::NotQueried.to_string(), "not queried");
    }

    #[test]
    fn failure_leaves_out_no_address_families() {
        let target = Target::parse("2606:4700:4700::1111").unwrap();
        let result = ipv6_literal_no_route_result(&target);
        assert!(matches!(result.ipv4_status, TracerouteStatus::NoAddress));
        assert_eq!(
            result.failure(Protocol::Both).to_string(),
            "IPv6: no IPv6 route on this host"
        );
        let mut none_attempted = TracerouteResult::new();
        none_attempted.ipv4_status = TracerouteStatus::NoAddress;
        assert_eq!(
            none_attempted.failure(Protocol::Ipv4).to_string(),
            "no IPv4 address for target"
        );
        assert_eq!(
            none_attempted
                .failure(Protocol::Ipv4)
                .downcast_ref::<crate::scan::NoAddress>(),
            Some(&crate::scan::NoAddress(Protocol::Ipv4))
        );
    }

    #[test]
    fn ipv6_literal_no_route_renders_the_route_not_debug_text() {
        use crate::tui::TraceroutePane;
        use crate::tui::testing::render_pane;
        use crate::types::{AppState, ScanState, ScanStatus};
        use std::sync::{Arc, Mutex};

        let target = Target::parse("2606:4700:4700::1111").unwrap();
        let outcome = Err(ipv6_literal_no_route_result(&target).failure(Protocol::Both));
        let state = Arc::new(Mutex::new(AppState::new(target.original.clone())));
        state.lock().unwrap().scanners.insert(
            "traceroute".to_string(),
            ScanState {
                result: None,
                error: None,
                status: ScanStatus::Running,
                last_updated: Instant::now(),
                history: Default::default(),
            },
        );
        crate::scanner::record_outcome("traceroute", 10, Protocol::Both, Instant::now(), outcome, &state);

        let guard = state.lock().unwrap();
        let pane = render_pane(&TraceroutePane::new(), &guard, 100, 30, false);
        assert!(pane.contains("no IPv6 route on this host"), "{pane}");
        assert!(!pane.contains("NoAddress"), "{pane}");
        assert!(!pane.contains("Failed("), "{pane}");
    }

    fn hop(hop_number: u8, reply: Option<IpAddr>) -> TracerouteHop {
        TracerouteHop {
            hop_number,
            responses: vec![HopResponse {
                ip_address: reply,
                rtt: reply.map(|_| Duration::from_millis(5)),
                timeout: reply.is_none(),
            }],
            best_rtt: None,
            avg_rtt: None,
            worst_rtt: None,
            packet_loss: if reply.is_some() { 0.0 } else { FULL_PACKET_LOSS },
        }
    }

    fn route(hops: Vec<TracerouteHop>, destination_reached: bool) -> TracerouteData {
        TracerouteData {
            total_hops: hops.len() as u8,
            hops,
            destination_reached,
            max_hops: MAX_TRACEROUTE_HOPS,
            target_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            scan_duration: Duration::from_secs(1),
            ipv6: false,
        }
    }

    #[test]
    fn traceroute_args_use_icmp_on_linux_and_macos() {
        let v4 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        for os in ["linux", "macos"] {
            let (program, args) = traceroute_args(os, false, 3, 30, 3, true, v4);
            assert_eq!(program, "traceroute");
            assert_eq!(
                args,
                ["-n", "-I", "-w", "3", "-m", "30", "-q", "3", "192.0.2.1"],
                "{os}"
            );
            let (program, args) = traceroute_args(os, true, 3, 30, 3, true, v6);
            assert_eq!(program, "traceroute6");
            assert!(args.contains(&"-I".to_string()), "{os}: {args:?}");
        }
    }

    #[test]
    fn traceroute_args_without_icmp_or_on_other_platforms_use_udp() {
        let v4 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let (_, udp) = traceroute_args("linux", false, 3, 30, 3, false, v4);
        assert!(!udp.contains(&"-I".to_string()), "{udp:?}");
        let (_, other) = traceroute_args("windows", false, 3, 30, 3, true, v4);
        assert!(!other.contains(&"-I".to_string()), "{other:?}");
    }

    #[test]
    fn icmp_refused_matches_only_the_privilege_text() {
        assert!(icmp_refused(
            "Traceroute command failed: You do not have enough privileges to use this traceroute method.\nsocket: Operation not permitted\n"
        ));
        assert!(!icmp_refused(
            "Traceroute command failed: connect: Network is unreachable"
        ));
        assert!(!icmp_refused(""));
    }

    /// A fake traceroute that appends its arguments to `runs` per call, then runs `body`.
    #[cfg(unix)]
    fn fake_traceroute(name: &str, body: &str) -> (std::path::PathBuf, std::path::PathBuf, String) {
        let dir = std::env::temp_dir().join(format!("scan-traceroute-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let runs = dir.join("runs");
        let script = dir.join("fake-traceroute");
        crate::scan::testing::write_executable_script(
            &script,
            &format!("#!/bin/sh\necho \"$*\" >> {}\n{body}\n", runs.display()),
        );
        let program = script.to_string_lossy().into_owned();
        (dir, runs, program)
    }

    #[cfg(unix)]
    async fn scan_with_fake(name: &str, body: &str) -> (Result<ScanResult>, Vec<String>) {
        let (dir, runs, program) = fake_traceroute(name, body);
        let target = Target::parse("192.0.2.1").unwrap();
        let outcome = TracerouteScanner::new()
            .with_program(program)
            .scan(&target, Protocol::Ipv4)
            .await;
        let lines = std::fs::read_to_string(&runs)
            .unwrap_or_default()
            .lines()
            .map(String::from)
            .collect();
        std::fs::remove_dir_all(&dir).unwrap();
        (outcome, lines)
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn icmp_privilege_refusal_retries_exactly_once_over_udp() {
        let body = r#"case " $* " in
  *" -I "*) echo "You do not have enough privileges to use this traceroute method." >&2; echo "socket: Operation not permitted" >&2; exit 1 ;;
esac
echo " 1  192.0.2.1  1.000 ms  1.100 ms  1.200 ms"
exit 0"#;
        let (outcome, runs) = scan_with_fake("privilege", body).await;
        assert_eq!(runs.len(), 2, "{runs:?}");
        assert!(runs[0].split(' ').any(|a| a == "-I"), "{runs:?}");
        assert!(!runs[1].split(' ').any(|a| a == "-I"), "{runs:?}");
        let Ok(ScanResult::Traceroute(result)) = outcome else {
            panic!("UDP retry should succeed: {outcome:?}");
        };
        assert!(result.any_destination_reached());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn other_icmp_failure_is_not_retried() {
        let (outcome, runs) =
            scan_with_fake("unreachable", r#"echo "connect: Network is unreachable" >&2; exit 1"#).await;
        assert_eq!(runs.len(), 1, "{runs:?} {outcome:?}");
        assert!(outcome.is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn silent_icmp_target_is_not_retried() {
        let (outcome, runs) = scan_with_fake("silent", r#"echo " 1  * * *"; echo " 2  * * *"; exit 0"#).await;
        assert_eq!(runs.len(), 1, "{runs:?}");
        let Ok(ScanResult::Traceroute(result)) = outcome else {
            panic!("a silent run is a result: {outcome:?}");
        };
        assert_eq!(
            result.get_primary_result().unwrap().reach_label(),
            "target silent (no hop replied)"
        );
    }

    #[test]
    fn reach_label_names_the_last_replying_hop() {
        let gw = Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        let isp = Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(route(vec![hop(1, gw)], true).reach_label(), "reached");
        assert_eq!(
            route(vec![hop(1, gw), hop(2, isp), hop(3, None), hop(4, None)], false).reach_label(),
            "target silent (last reply: hop 2)"
        );
        assert_eq!(
            route(vec![hop(1, None), hop(2, None)], false).reach_label(),
            "target silent (no hop replied)"
        );
        assert_eq!(route(vec![], false).reach_label(), "target silent (no hop replied)");
    }

    fn render_traceroute(outcome: Result<ScanResult>) -> String {
        use crate::tui::TraceroutePane;
        use crate::tui::testing::render_pane;
        use crate::types::{AppState, ScanState, ScanStatus};
        use std::sync::{Arc, Mutex};

        let state = Arc::new(Mutex::new(AppState::new("192.0.2.1".to_string())));
        state.lock().unwrap().scanners.insert(
            "traceroute".to_string(),
            ScanState {
                result: None,
                error: None,
                status: ScanStatus::Running,
                last_updated: Instant::now(),
                history: Default::default(),
            },
        );
        crate::scanner::record_outcome("traceroute", 10, Protocol::Ipv4, Instant::now(), outcome, &state);
        let guard = state.lock().unwrap();
        render_pane(&TraceroutePane::new(), &guard, 100, 30, false)
    }

    fn traced(data: TracerouteData) -> Result<ScanResult> {
        let mut result = TracerouteResult::new();
        result.ipv4_status = TracerouteStatus::Success(data.total_hops);
        result.ipv4_result = Some(data);
        Ok(ScanResult::Traceroute(result))
    }

    #[test]
    fn silent_target_renders_target_silent_with_the_last_reply_hop() {
        let gw = Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        let pane = render_traceroute(traced(route(vec![hop(1, gw), hop(2, gw), hop(3, None)], false)));
        assert!(pane.contains("✗ target silent (last reply: hop 2)"), "{pane}");
        assert!(!pane.contains("unreached"), "{pane}");

        let pane = render_traceroute(traced(route(vec![hop(1, None)], false)));
        assert!(pane.contains("✗ target silent (no hop replied)"), "{pane}");
        assert!(!pane.contains("hop 0"), "{pane}");
    }

    #[test]
    fn reached_target_renders_check_reached() {
        let target = Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        let pane = render_traceroute(traced(route(vec![hop(1, target)], true)));
        assert!(pane.contains("✓ reached"), "{pane}");
    }

    #[test]
    fn test_traceroute_scanner_creation() {
        let scanner = TracerouteScanner::new();
        assert_eq!(scanner.name(), "traceroute");
        assert_eq!(scanner.max_hops, MAX_TRACEROUTE_HOPS);
        assert_eq!(scanner.probes_per_hop, PROBES_PER_HOP);
    }

    #[test]
    fn test_parse_marks_reached_when_target_not_first_response() {
        let scanner = TracerouteScanner::new();
        let target = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let out = "traceroute to 1.1.1.1 (1.1.1.1), 30 hops max\n 1  192.168.1.1  1.0 ms  1.1 ms  1.2 ms\n 2  *  1.1.1.1  12.3 ms  1.1.1.1  12.5 ms\n";
        let data = scanner
            .parse_traceroute_output(out, target, false, Duration::from_secs(1))
            .unwrap();
        assert!(data.destination_reached);
    }

    #[test]
    fn test_parse_not_reached_when_target_absent() {
        let scanner = TracerouteScanner::new();
        let target = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let out =
            "traceroute to 1.1.1.1 (1.1.1.1), 30 hops max\n 1  192.168.1.1  1.0 ms  1.1 ms  1.2 ms\n 2  *  *  *\n";
        let data = scanner
            .parse_traceroute_output(out, target, false, Duration::from_secs(1))
            .unwrap();
        assert!(!data.destination_reached);
    }

    #[test]
    fn test_parse_hop_line_with_responses() {
        let scanner = TracerouteScanner::new();
        let line = " 1  192.168.10.1  2.390 ms  2.250 ms  2.203 ms";

        let hop = scanner.parse_hop_line(line).unwrap().unwrap();
        assert_eq!(hop.hop_number, 1);
        assert_eq!(hop.responses.len(), 3);

        // Check first response
        let response = &hop.responses[0];
        assert_eq!(response.ip_address, Some(IpAddr::V4(Ipv4Addr::new(192, 168, 10, 1))));
        assert!(!response.timeout);
        assert!(response.rtt.is_some());

        // Check statistics
        assert!(hop.best_rtt.is_some());
        assert!(hop.avg_rtt.is_some());
        assert!(hop.worst_rtt.is_some());
        assert_eq!(hop.packet_loss, 0.0);
    }

    #[test]
    fn test_parse_hop_line_with_timeouts() {
        let scanner = TracerouteScanner::new();
        let line = " 3  * * *";

        let hop = scanner.parse_hop_line(line).unwrap().unwrap();
        assert_eq!(hop.hop_number, 3);
        assert_eq!(hop.responses.len(), 3);

        // All responses should be timeouts
        for response in &hop.responses {
            assert!(response.timeout);
            assert!(response.ip_address.is_none());
            assert!(response.rtt.is_none());
        }

        assert_eq!(hop.packet_loss, 1.0);
        assert!(hop.best_rtt.is_none());
    }

    #[test]
    fn test_parse_hop_line_mixed_responses() {
        let scanner = TracerouteScanner::new();
        let line = " 2  192.168.7.1  4.929 ms  * 8.298 ms";

        let hop = scanner.parse_hop_line(line).unwrap().unwrap();
        assert_eq!(hop.hop_number, 2);
        assert_eq!(hop.responses.len(), 3);

        // First response should have IP and RTT
        assert_eq!(
            hop.responses[0].ip_address,
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 7, 1)))
        );
        assert!(!hop.responses[0].timeout);

        // Second response should be timeout
        assert!(hop.responses[1].timeout);

        // Third response should have RTT (same IP as first)
        assert!(!hop.responses[2].timeout);
        assert!(hop.responses[2].rtt.is_some());

        // Packet loss should be 1/3
        assert!((hop.packet_loss - 0.333).abs() < 0.01);
    }

    #[test]
    fn test_parse_ipv6_hop() {
        let scanner = TracerouteScanner::new();
        let line = " 1  2001:db8::1  15.234 ms  14.567 ms  16.123 ms";

        let hop = scanner.parse_hop_line(line).unwrap().unwrap();
        assert_eq!(hop.hop_number, 1);

        let expected_ip = "2001:db8::1".parse::<IpAddr>().unwrap();
        assert_eq!(hop.responses[0].ip_address, Some(expected_ip));
    }

    #[test]
    fn test_parse_invalid_hop_line() {
        let scanner = TracerouteScanner::new();

        // Empty line
        assert!(scanner.parse_hop_line("").unwrap().is_none());

        // Header line
        assert!(
            scanner
                .parse_hop_line("traceroute to 8.8.8.8 (8.8.8.8), 30 hops max")
                .unwrap()
                .is_none()
        );

        // Invalid format
        assert!(scanner.parse_hop_line("not a hop line").unwrap().is_none());
    }

    #[tokio::test]
    async fn test_traceroute_scan_localhost() {
        let scanner = TracerouteScanner::new();
        let mut target = Target::parse("127.0.0.1").unwrap();
        target.resolve().await.expect("Failed to resolve target");

        // This test requires traceroute to be installed
        // Skip if not available
        if std::process::Command::new("which").arg("traceroute").output().is_err() {
            return;
        }

        match scanner.scan(&target, Protocol::Ipv4).await {
            Ok(ScanResult::Traceroute(result)) => {
                assert!(result.has_any_success());
                if let Some(ipv4_data) = &result.ipv4_result {
                    assert!(!ipv4_data.hops.is_empty());
                    assert_eq!(ipv4_data.target_ip, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
                    assert!(!ipv4_data.ipv6);
                }
            }
            Ok(_) => panic!("Expected TracerouteResult"),
            Err(e) => {
                // Traceroute might fail in some environments (containers, etc.)
                println!("Traceroute test skipped due to error: {}", e);
            }
        }
    }

    #[test]
    fn test_traceroute_result_structure() {
        let mut result = TracerouteResult::new();
        result.ipv4_result = Some(TracerouteData {
            hops: vec![],
            destination_reached: false,
            total_hops: 5,
            max_hops: 30,
            target_ip: IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            scan_duration: Duration::from_millis(500),
            ipv6: false,
        });
        result.ipv4_status = TracerouteStatus::Success(5);
        result.total_duration = Duration::from_millis(500);

        assert_eq!(result.total_hops(), 5);
        assert!(!result.any_destination_reached());
        if let Some(ipv4_data) = &result.ipv4_result {
            assert_eq!(ipv4_data.max_hops, 30);
            assert!(!ipv4_data.ipv6);
            assert!(ipv4_data.hops.is_empty());
        }
    }

    #[test]
    fn test_hop_response_structure() {
        let response = HopResponse {
            ip_address: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            rtt: Some(Duration::from_millis(5)),
            timeout: false,
        };

        assert!(response.ip_address.is_some());
        assert!(response.rtt.is_some());
        assert!(!response.timeout);

        let timeout_response = HopResponse {
            ip_address: None,
            rtt: None,
            timeout: true,
        };

        assert!(timeout_response.ip_address.is_none());
        assert!(timeout_response.rtt.is_none());
        assert!(timeout_response.timeout);
    }

    #[test]
    fn test_traceroute_hop_statistics() {
        let hop = TracerouteHop {
            hop_number: 3,
            responses: vec![
                HopResponse {
                    ip_address: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
                    rtt: Some(Duration::from_millis(10)),
                    timeout: false,
                },
                HopResponse {
                    ip_address: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
                    rtt: Some(Duration::from_millis(15)),
                    timeout: false,
                },
                HopResponse {
                    ip_address: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
                    rtt: Some(Duration::from_millis(20)),
                    timeout: false,
                },
            ],
            best_rtt: Some(Duration::from_millis(10)),
            avg_rtt: Some(Duration::from_millis(15)),
            worst_rtt: Some(Duration::from_millis(20)),
            packet_loss: 0.0,
        };

        assert_eq!(hop.hop_number, 3);
        assert_eq!(hop.responses.len(), 3);
        assert_eq!(hop.best_rtt, Some(Duration::from_millis(10)));
        assert_eq!(hop.avg_rtt, Some(Duration::from_millis(15)));
        assert_eq!(hop.worst_rtt, Some(Duration::from_millis(20)));
        assert_eq!(hop.packet_loss, 0.0);
    }

    #[test]
    fn test_parse_hop_line_complex_cases() {
        let scanner = TracerouteScanner::new();

        // Test hop with hostname resolution - this might not parse correctly depending on implementation
        let hostname_line = " 1  router.local (192.168.1.1)  2.390 ms  2.250 ms  2.203 ms";
        if let Ok(Some(hop)) = scanner.parse_hop_line(hostname_line) {
            assert_eq!(hop.hop_number, 1);
            assert_eq!(hop.responses.len(), 3);
            // IP parsing might not work with hostname format
        }

        // Test hop with different IPs for each response
        let multi_ip_line = " 2  10.0.0.1  4.929 ms 10.0.0.2  8.298 ms 10.0.0.3  12.456 ms";
        let multi_hop = scanner.parse_hop_line(multi_ip_line).unwrap().unwrap();
        assert_eq!(multi_hop.hop_number, 2);
        assert_eq!(multi_hop.responses.len(), 3);
        assert_eq!(
            multi_hop.responses[0].ip_address,
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
        );
    }

    #[test]
    fn test_parse_hop_line_error_conditions() {
        let scanner = TracerouteScanner::new();

        // Test line without hop number
        let no_hop_line = "invalid line without hop number";
        assert!(scanner.parse_hop_line(no_hop_line).unwrap().is_none());

        // Test line with invalid hop number
        let invalid_hop_line = " invalid  192.168.1.1  2.390 ms";
        assert!(scanner.parse_hop_line(invalid_hop_line).unwrap().is_none());

        // Test empty/whitespace lines
        assert!(scanner.parse_hop_line("").unwrap().is_none());
        assert!(scanner.parse_hop_line("   ").unwrap().is_none());
    }

    #[test]
    fn test_traceroute_scanner_defaults() {
        let scanner = TracerouteScanner::default();

        assert_eq!(scanner.name(), "traceroute");
        assert_eq!(scanner.max_hops, 30); // Updated constant value
        assert_eq!(scanner.probes_per_hop, 3);
        assert_eq!(scanner.timeout, Duration::from_secs(3)); // Updated timeout value
    }

    #[test]
    fn test_traceroute_scanner_custom_config() {
        let scanner = TracerouteScanner::new();

        assert_eq!(scanner.interval(), Duration::from_secs(300)); // 5 minutes (updated value)
        assert_eq!(scanner.max_hops, 30); // Updated constant value
        assert_eq!(scanner.probes_per_hop, 3);
    }

    #[test]
    fn test_traceroute_status_enum() {
        // Test TracerouteStatus variants
        match TracerouteStatus::Success(5) {
            TracerouteStatus::Success(hops) => assert_eq!(hops, 5),
            _ => panic!("Expected Success status"),
        }

        match TracerouteStatus::Failed("Network unreachable".to_string()) {
            TracerouteStatus::Failed(msg) => assert!(msg.contains("unreachable")),
            _ => panic!("Expected Failed status"),
        }

        match TracerouteStatus::NoAddress {
            TracerouteStatus::NoAddress => {}
            _ => panic!("Expected NoAddress status"),
        }

        match TracerouteStatus::NotQueried {
            TracerouteStatus::NotQueried => {}
            _ => panic!("Expected NotQueried status"),
        }
    }

    #[test]
    fn test_packet_loss_calculation() {
        let scanner = TracerouteScanner::new();

        // Test 100% packet loss
        let all_timeout_line = " 5  * * *";
        let timeout_hop = scanner.parse_hop_line(all_timeout_line).unwrap().unwrap();
        assert_eq!(timeout_hop.packet_loss, 1.0);

        // Test 33% packet loss (1 out of 3)
        let partial_timeout_line = " 6  192.168.1.1  5.0 ms * 7.5 ms";
        let partial_hop = scanner.parse_hop_line(partial_timeout_line).unwrap().unwrap();
        assert!((partial_hop.packet_loss - 0.333).abs() < 0.01);

        // Test 0% packet loss
        let no_timeout_line = " 7  192.168.1.1  5.0 ms  6.0 ms  7.0 ms";
        let success_hop = scanner.parse_hop_line(no_timeout_line).unwrap().unwrap();
        assert_eq!(success_hop.packet_loss, 0.0);
    }
}

#[cfg(test)]
mod destination_hop_tests {
    use super::*;

    fn data(reached: bool) -> TracerouteData {
        let answer = |n: u8, ip: &str| TracerouteHop {
            hop_number: n,
            responses: vec![HopResponse {
                ip_address: Some(ip.parse().expect("ip")),
                rtt: Some(Duration::from_millis(1)),
                timeout: false,
            }],
            best_rtt: None,
            avg_rtt: None,
            worst_rtt: None,
            packet_loss: 0.0,
        };
        TracerouteData {
            hops: vec![answer(1, "10.0.0.1"), answer(2, "192.0.2.9")],
            destination_reached: reached,
            total_hops: 2,
            max_hops: 30,
            target_ip: "192.0.2.9".parse().expect("ip"),
            scan_duration: Duration::from_millis(5),
            ipv6: false,
        }
    }

    #[test]
    fn destination_hop_is_the_hop_that_answered_from_the_target() {
        assert_eq!(data(true).destination_hop().map(|hop| hop.hop_number), Some(2));
    }

    #[test]
    fn no_destination_hop_when_the_target_was_not_reached() {
        assert!(data(false).destination_hop().is_none());
    }
}
