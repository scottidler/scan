pub mod cache;
pub mod connect;
pub mod dns;
pub mod geoip;
pub mod http;
pub mod ping;
pub mod port;
pub mod psl;
#[cfg(test)]
pub mod testing;
pub mod tls;
pub mod traceroute;
pub mod whois;

pub use dns::{DnsResult, DnsScanner};
pub use geoip::{GeoIpResult, GeoIpScanner};
pub use http::{HttpResult, HttpScanner};
pub use ping::{PingResult, PingScanner};
pub use port::{PortResult, PortScanner};
pub use tls::{TlsResult, TlsScanner};
pub use traceroute::{TracerouteResult, TracerouteScanner};
pub use whois::{WhoisResult, WhoisScanner};

use crate::scanner::Scanner;
use crate::target::{Protocol, Target};
use std::ffi::OsStr;
use std::fmt;
use std::sync::{Arc, Mutex};
use tokio::process::Command;
use tokio::sync::watch;

/// One IP address family, for per-family scan outcomes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    Ipv4,
    Ipv6,
}

impl Family {
    pub fn as_str(&self) -> &'static str {
        match self {
            Family::Ipv4 => "IPv4",
            Family::Ipv6 => "IPv6",
        }
    }

    /// The family `ip` belongs to.
    pub fn of_ip(ip: std::net::IpAddr) -> Self {
        if ip.is_ipv4() { Family::Ipv4 } else { Family::Ipv6 }
    }

    /// The family a single-family protocol selects; `None` for `Protocol::Both`.
    pub fn from_protocol(protocol: Protocol) -> Option<Self> {
        match protocol {
            Protocol::Ipv4 => Some(Family::Ipv4),
            Protocol::Ipv6 => Some(Family::Ipv6),
            Protocol::Both => None,
        }
    }
}

impl fmt::Display for Family {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A network failure, split into "this host has no route for the family" and everything else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteError {
    NoRoute(Family),
    Other(String),
}

impl fmt::Display for RouteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RouteError::NoRoute(family) => write!(f, "no {family} route on this host"),
            RouteError::Other(reason) => f.write_str(reason),
        }
    }
}

/// True when `text` carries the errno as Rust's io::Error prints it (`(os error N)`) or as the
/// C tools print its strerror (`connect: Network is unreachable`).
fn mentions_errno(text: &str, errno: u8, strerror: &str) -> bool {
    text.contains(&format!("(os error {errno})")) || text.to_lowercase().contains(&strerror.to_lowercase())
}

/// Classify a failure's text for `family`.
///
/// - ENETUNREACH (101): this host has no route for the family.
/// - EADDRNOTAVAIL (99): on IPv6, no source address, so no route; on IPv4 it also means
///   ephemeral-port exhaustion (`man 2 connect`), so it stays `Other`.
/// - EHOSTUNREACH (113): a remote condition, reported as `host unreachable`, never as a
///   missing route on this host.
pub fn classify_route_error(text: &str, family: Family) -> RouteError {
    let route = if mentions_errno(text, 101, "Network is unreachable") {
        RouteError::NoRoute(family)
    } else if family == Family::Ipv6 && mentions_errno(text, 99, "Cannot assign requested address") {
        RouteError::NoRoute(Family::Ipv6)
    } else if mentions_errno(text, 113, "No route to host") {
        RouteError::Other("host unreachable".to_string())
    } else {
        RouteError::Other(text.to_string())
    };
    log::debug!(
        "[scan] classify_route_error: family={} text={:?} route={:?}",
        family,
        text,
        route
    );
    route
}

/// The aggregate message for a scan whose every family failed: `IPv4: <reason>; IPv6: <reason>`.
/// Families with no address are left out; when none was attempted, the message says so.
pub fn family_failure_summary(failures: &[(Family, String)], protocol: Protocol) -> String {
    if failures.is_empty() {
        return format!("no {} address for target", protocol.as_str());
    }
    failures
        .iter()
        .map(|(family, reason)| format!("{family}: {reason}"))
        .collect::<Vec<_>>()
        .join("; ")
}

pub fn create_default_scanners() -> Vec<Box<dyn Scanner + Send + Sync>> {
    log::debug!("[scan] create_default_scanners: creating scanner instances");

    let scanners: Vec<Box<dyn Scanner + Send + Sync>> = vec![
        Box::new(PingScanner::default()),
        Box::new(DnsScanner::new()),
        Box::new(TlsScanner::new()),
        Box::new(HttpScanner::default()),
        Box::new(WhoisScanner::default()),
        Box::new(TracerouteScanner::new()),
        Box::new(GeoIpScanner::new()),
        Box::new(PortScanner::new()),
    ];

    log::debug!("[scan] scanners_created: count={}", scanners.len());
    scanners
}

/// Build a child-process command that is killed when its handle is dropped, so a cancelled or
/// timed-out scan never leaves `ping`/`traceroute` running behind it.
pub fn kill_on_drop_command(program: impl AsRef<OsStr>) -> Command {
    let mut command = Command::new(program);
    command.kill_on_drop(true);
    command
}

/// Spawn one task per scanner. Each task follows the protocol through its own clone of
/// `protocol_rx`; the sender stays with the caller.
pub async fn spawn_scanner_tasks(
    scanners: Vec<Box<dyn Scanner + Send + Sync>>,
    target: Target,
    protocol_rx: watch::Receiver<Protocol>,
    state: Arc<Mutex<crate::types::AppState>>,
) {
    let initial_protocol = *protocol_rx.borrow();
    log::debug!(
        "[scan] spawn_scanner_tasks: scanner_count={} target={} protocol={}",
        scanners.len(),
        target.display_name(),
        initial_protocol.as_str()
    );

    for scanner in scanners {
        let scanner_name = scanner.name();
        let target_clone = target.clone();
        let state_clone = state.clone();
        let protocol_rx = protocol_rx.clone();

        log::debug!(
            "[scan] spawning_scanner_task: scanner={} protocol={}",
            scanner_name,
            initial_protocol.as_str()
        );

        tokio::spawn(async move {
            log::debug!("[scan] scanner_task_started: scanner={}", scanner_name);
            scanner.run(target_clone, protocol_rx, state_clone).await;
            log::debug!("[scan] scanner_task_ended: scanner={}", scanner_name);
        });
    }

    log::debug!(
        "[scan] all_scanner_tasks_spawned: protocol={}",
        initial_protocol.as_str()
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_route_error_maps_each_errno_by_family() {
        let cases = [
            (
                "Cannot assign requested address (os error 99)",
                Family::Ipv6,
                RouteError::NoRoute(Family::Ipv6),
            ),
            (
                "Cannot assign requested address (os error 99)",
                Family::Ipv4,
                RouteError::Other("Cannot assign requested address (os error 99)".to_string()),
            ),
            (
                "Network is unreachable (os error 101)",
                Family::Ipv4,
                RouteError::NoRoute(Family::Ipv4),
            ),
            (
                "Network is unreachable (os error 101)",
                Family::Ipv6,
                RouteError::NoRoute(Family::Ipv6),
            ),
            (
                "No route to host (os error 113)",
                Family::Ipv6,
                RouteError::Other("host unreachable".to_string()),
            ),
            (
                "No route to host (os error 113)",
                Family::Ipv4,
                RouteError::Other("host unreachable".to_string()),
            ),
        ];
        for (text, family, expected) in cases {
            assert_eq!(classify_route_error(text, family), expected, "{text} on {family}");
        }
    }

    #[test]
    fn classify_route_error_reads_tool_strerror_without_errno() {
        assert_eq!(
            classify_route_error("connect: Cannot assign requested address", Family::Ipv6),
            RouteError::NoRoute(Family::Ipv6)
        );
        assert_eq!(
            classify_route_error("ping: connect: Network is unreachable", Family::Ipv4),
            RouteError::NoRoute(Family::Ipv4)
        );
        assert_eq!(
            classify_route_error("operation timed out", Family::Ipv4),
            RouteError::Other("operation timed out".to_string())
        );
    }

    #[test]
    fn route_error_display_never_blames_this_host_for_113() {
        assert_eq!(
            RouteError::NoRoute(Family::Ipv6).to_string(),
            "no IPv6 route on this host"
        );
        let remote = classify_route_error("No route to host (os error 113)", Family::Ipv6).to_string();
        assert_eq!(remote, "host unreachable");
        assert!(!remote.contains("on this host"));
    }

    #[test]
    fn family_of_ip_follows_the_address() {
        assert_eq!(Family::of_ip("192.0.2.1".parse().unwrap()), Family::Ipv4);
        assert_eq!(Family::of_ip("2001:db8::1".parse().unwrap()), Family::Ipv6);
    }

    #[test]
    fn family_failure_summary_joins_families_and_names_the_empty_case() {
        let failures = vec![
            (Family::Ipv4, "operation timed out".to_string()),
            (Family::Ipv6, "no IPv6 route on this host".to_string()),
        ];
        assert_eq!(
            family_failure_summary(&failures, Protocol::Both),
            "IPv4: operation timed out; IPv6: no IPv6 route on this host"
        );
        assert_eq!(
            family_failure_summary(&[], Protocol::Ipv6),
            "no IPv6 address for target"
        );
    }

    #[test]
    fn kill_on_drop_command_sets_kill_on_drop() {
        assert!(kill_on_drop_command("ping").get_kill_on_drop());
        assert!(
            !Command::new("ping").get_kill_on_drop(),
            "tokio's default is to leave the child running"
        );
    }
}
