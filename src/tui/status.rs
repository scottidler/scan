//! Shared status-line label for panes whose data comes from a scanner.

use crate::scan::NoAddress;
use crate::target::Protocol;
use crate::tui::theme;
use crate::types::{ScanState, ScanStatus};
use ratatui::style::Color;

/// Marker shown while a scanner re-runs and the pane still displays its previous result.
pub const REFRESHING_LABEL: &str = "↻ refreshing";

/// Marker appended to a failure while the scanner runs its next attempt.
pub const RETRYING_LABEL: &str = "↻ retrying";

/// Text and color for a pane's `Status:` line.
///
/// A `Running` scanner whose last attempt failed keeps naming that failure until the retry
/// lands, so the reason does not vanish for the length of a scan. Otherwise a `Running` scanner
/// that already holds a result is a refresh, not a first scan, so the retained data is marked
/// `↻ refreshing` instead of claiming to be fresh or blank. A `Failed` scanner names its error,
/// whether or not an older result is still on screen below it. A scanner whose last attempt
/// found no target address in the selected protocol is not a fault: it reads `no IPv6 address`
/// in MUTED, while failed or re-running, and never `failed:`.
pub fn status_label(scan_state: &ScanState, running: &'static str, complete: &'static str) -> (String, Color) {
    if !matches!(scan_state.status, ScanStatus::Complete)
        && let Some(protocol) = no_address(scan_state)
    {
        return (format!("no {} address", protocol.as_str()), theme::MUTED);
    }
    match scan_state.status {
        ScanStatus::Running => match (&scan_state.error, &scan_state.result) {
            (Some(error), _) => (format!("failed: {error:#} · {RETRYING_LABEL}"), theme::BAD),
            (None, Some(_)) => (REFRESHING_LABEL.to_string(), theme::WARN),
            (None, None) => (running.to_string(), theme::WARN),
        },
        ScanStatus::Complete => (complete.to_string(), theme::GOOD),
        ScanStatus::Failed => (
            failure_text(scan_state).unwrap_or_else(|| "failed".to_string()),
            theme::BAD,
        ),
    }
}

/// `failed: <error>` for a `Failed` scanner that recorded an error, `None` otherwise. A
/// [`NoAddress`] outcome is not a failure, so it is `None` too.
pub fn failure_text(scan_state: &ScanState) -> Option<String> {
    match (&scan_state.status, &scan_state.error) {
        (ScanStatus::Failed, Some(error)) if error.downcast_ref::<NoAddress>().is_none() => {
            Some(format!("failed: {error:#}"))
        }
        _ => None,
    }
}

/// The protocol the scanner's last attempt had no target address for, if it ended that way.
pub fn no_address(scan_state: &ScanState) -> Option<Protocol> {
    scan_state
        .error
        .as_ref()?
        .downcast_ref::<NoAddress>()
        .map(|no_address| no_address.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::ping::PingResult;
    use crate::types::ScanResult;
    use std::collections::VecDeque;
    use std::time::Instant;

    fn scan_state(status: ScanStatus, with_result: bool) -> ScanState {
        ScanState {
            result: with_result.then(|| ScanResult::Ping(PingResult::new())),
            error: None,
            status,
            last_updated: Instant::now(),
            history: VecDeque::new(),
        }
    }

    #[test]
    fn running_without_result_uses_first_scan_text() {
        let (label, _) = status_label(&scan_state(ScanStatus::Running, false), "scanning...", "done");
        assert_eq!(label, "scanning...");
    }

    #[test]
    fn running_with_result_is_refreshing() {
        let (label, color) = status_label(&scan_state(ScanStatus::Running, true), "scanning...", "done");
        assert_eq!(label, REFRESHING_LABEL);
        assert_eq!(color, Color::Yellow);
    }

    #[test]
    fn complete_and_failed_labels() {
        assert_eq!(
            status_label(&scan_state(ScanStatus::Complete, true), "r", "done").0,
            "done"
        );
        assert_eq!(
            status_label(&scan_state(ScanStatus::Failed, false), "r", "done").0,
            "failed"
        );
    }

    #[test]
    fn failed_with_error_names_the_reason() {
        let mut state = scan_state(ScanStatus::Failed, false);
        state.error = Some(eyre::eyre!("timed out after 30s"));
        let (label, color) = status_label(&state, "r", "done");
        assert_eq!(label, "failed: timed out after 30s");
        assert_eq!(color, Color::LightRed);
    }

    #[test]
    fn failed_with_retained_result_still_names_the_reason() {
        let mut state = scan_state(ScanStatus::Failed, true);
        state.error = Some(eyre::eyre!("connection refused"));
        assert_eq!(status_label(&state, "r", "done").0, "failed: connection refused");
    }

    #[test]
    fn running_after_a_failure_keeps_the_reason_while_retrying() {
        for with_result in [false, true] {
            let mut state = scan_state(ScanStatus::Running, with_result);
            state.error = Some(eyre::eyre!("timed out after 30s"));
            let (label, color) = status_label(&state, "scanning...", "done");
            assert!(label.contains("failed:"), "{label}");
            assert_eq!(label, "failed: timed out after 30s · ↻ retrying");
            assert_eq!(color, Color::LightRed);
        }
    }

    #[test]
    fn no_address_reads_muted_never_failed_while_failed_or_retrying() {
        for status in [ScanStatus::Failed, ScanStatus::Running] {
            let mut state = scan_state(status, false);
            state.error = Some(eyre::Report::new(NoAddress(Protocol::Ipv6)));
            let (label, color) = status_label(&state, "scanning...", "done");
            assert_eq!(label, "no IPv6 address");
            assert_eq!(color, theme::MUTED);
            assert_eq!(no_address(&state), Some(Protocol::Ipv6));
        }
        let mut state = scan_state(ScanStatus::Failed, false);
        state.error = Some(eyre::Report::new(NoAddress(Protocol::Ipv4)));
        assert!(failure_text(&state).is_none());
        assert_eq!(status_label(&state, "r", "done").0, "no IPv4 address");
    }

    #[test]
    fn a_family_with_an_address_that_fails_stays_bad() {
        let mut state = scan_state(ScanStatus::Failed, false);
        state.error = Some(crate::scan::family_failure(
            &[(crate::scan::Family::Ipv6, "operation timed out".to_string())],
            Protocol::Ipv6,
        ));
        let (label, color) = status_label(&state, "r", "done");
        assert_eq!(label, "failed: IPv6: operation timed out");
        assert_eq!(color, theme::BAD);
        assert_eq!(no_address(&state), None);
    }

    #[test]
    fn failure_text_is_none_unless_failed() {
        let mut state = scan_state(ScanStatus::Complete, true);
        state.error = Some(eyre::eyre!("stale"));
        assert!(failure_text(&state).is_none());
        assert!(failure_text(&scan_state(ScanStatus::Failed, false)).is_none());
    }
}
