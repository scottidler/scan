pub mod dns;
pub mod geoip;
pub mod http;
pub mod ping;
pub mod port;
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
use std::sync::{Arc, Mutex};
use tokio::process::Command;
use tokio::sync::watch;

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
    fn kill_on_drop_command_sets_kill_on_drop() {
        assert!(kill_on_drop_command("ping").get_kill_on_drop());
        assert!(
            !Command::new("ping").get_kill_on_drop(),
            "tokio's default is to leave the child running"
        );
    }
}
