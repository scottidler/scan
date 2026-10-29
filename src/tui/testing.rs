//! Test-only helper that renders a pane into a `TestBackend` buffer.

use crate::tui::pane::Pane;
use crate::types::AppState;
use ratatui::{Terminal, backend::TestBackend};

/// Render `pane` at `width` x `height` and return the buffer as newline-joined text rows.
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
        .map(|y| (0..width).map(|x| buffer[(x, y)].symbol()).collect::<String>())
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
}
