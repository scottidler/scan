//! Shared status-line label for panes whose data comes from a scanner.

use crate::types::{ScanState, ScanStatus};
use ratatui::style::Color;

/// Marker shown while a scanner re-runs and the pane still displays its previous result.
pub const REFRESHING_LABEL: &str = "↻ refreshing";

/// Text and color for a pane's `Status:` line.
///
/// A `Running` scanner that already holds a result is a refresh, not a first scan, so the
/// retained data is marked `↻ refreshing` instead of claiming to be fresh or blank.
pub fn status_label(scan_state: &ScanState, running: &'static str, complete: &'static str) -> (&'static str, Color) {
    match scan_state.status {
        ScanStatus::Running if scan_state.result.is_some() => (REFRESHING_LABEL, Color::Yellow),
        ScanStatus::Running => (running, Color::Yellow),
        ScanStatus::Complete => (complete, Color::Green),
        ScanStatus::Failed => ("failed", Color::Red),
    }
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
}
