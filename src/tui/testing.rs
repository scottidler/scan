//! Test-only helper that renders a pane into a `TestBackend` buffer.

use crate::tui::pane::Pane;
use crate::types::AppState;
use ratatui::{Terminal, backend::TestBackend, text::Span};

/// Render `pane` at `width` x `height` and return the buffer as newline-joined text rows.
/// The continuation cell after a double-width glyph is dropped, as a terminal shows it.
pub fn render_pane(pane: &dyn Pane, state: &AppState, width: u16, height: u16, focused: bool) -> String {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("TestBackend terminal");
    terminal
        .draw(|frame| {
            let area = frame.area();
            pane.render(frame, area, state, focused);
        })
        .expect("draw pane");
    let buffer = terminal.backend().buffer();
    (0..height)
        .map(|y| {
            let mut row = String::new();
            let mut x = 0;
            while x < width {
                let symbol = buffer[(x, y)].symbol();
                row.push_str(symbol);
                x += Span::raw(symbol).width().max(1) as u16;
            }
            row
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::*;

    fn assert_renders_title(pane: &dyn Pane) {
        let state = AppState::new("example.com".to_string());
        let out = render_pane(pane, &state, 80, 24, false);
        assert!(
            out.contains(&pane.title().to_uppercase()),
            "{} pane render missing title:\n{}",
            pane.title(),
            out
        );
    }

    #[test]
    fn render_target_title() {
        assert_renders_title(&TargetPane::new());
    }

    #[test]
    fn render_connectivity_title() {
        assert_renders_title(&ConnectivityPane::new());
    }

    #[test]
    fn render_whois_title() {
        assert_renders_title(&WhoisPane::new());
    }

    #[test]
    fn render_http_title() {
        assert_renders_title(&HttpPane::new());
    }

    #[test]
    fn render_ports_title() {
        assert_renders_title(&PortsPane::new());
    }

    #[test]
    fn render_geoip_title() {
        assert_renders_title(&GeoIpPane::new());
    }

    #[test]
    fn render_dns_title() {
        assert_renders_title(&DnsPane::new());
    }

    #[test]
    fn render_traceroute_title() {
        assert_renders_title(&TraceroutePane::new());
    }

    #[test]
    fn render_security_title() {
        assert_renders_title(&SecurityPane::new());
    }

    #[test]
    fn render_helper_distinguishes_wrong_title() {
        let state = AppState::new("example.com".to_string());
        let out = render_pane(&DnsPane::new(), &state, 80, 24, false);
        assert!(!out.contains("SECURITY"));
    }

    fn failed_first_scan(scanner: &str) -> AppState {
        let state = AppState::new("example.com".to_string());
        state.scanners.insert(
            scanner.to_string(),
            crate::types::ScanState {
                result: None,
                error: Some(eyre::eyre!("timed out after 30s")),
                status: crate::types::ScanStatus::Failed,
                last_updated: std::time::Instant::now(),
                history: std::collections::VecDeque::new(),
            },
        );
        state
    }

    #[test]
    fn every_status_pane_names_a_failed_first_scan() {
        let panes: Vec<(&str, Box<dyn Pane>)> = vec![
            ("ping", Box::new(ConnectivityPane::new())),
            ("dns", Box::new(DnsPane::new())),
            ("tls", Box::new(SecurityPane::new())),
            ("http", Box::new(HttpPane::new())),
            ("whois", Box::new(WhoisPane::new())),
            ("traceroute", Box::new(TraceroutePane::new())),
            ("geoip", Box::new(GeoIpPane::new())),
            ("port", Box::new(PortsPane::new())),
        ];
        for (scanner, pane) in panes {
            let out = render_pane(pane.as_ref(), &failed_first_scan(scanner), 100, 30, false);
            assert!(
                out.contains("failed: timed out after 30s"),
                "{scanner}: failure reason missing:\n{out}"
            );
            for pending in [
                "checking",
                "analyzing",
                "resolving",
                "scanning...",
                "querying",
                "locating",
                "tracing",
            ] {
                assert!(!out.contains(pending), "{scanner}: still shows `{pending}`:\n{out}");
            }
        }
    }
}
