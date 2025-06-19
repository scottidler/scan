use crate::tui::pane::{create_block, Pane};
use crate::tui::sparkline::SparklineData;
use crate::types::{AppState, ScanResult};
use ratatui::{
    layout::{Alignment, Rect, Layout, Constraint, Direction},
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Paragraph, Widget, Sparkline},
    Frame,
};
use std::any::Any;
use std::sync::Mutex;
use std::collections::VecDeque;
use std::time::Instant;
use log;




const MIN_CONNECTIVITY_PANE_WIDTH: u16 = 25;
const MIN_CONNECTIVITY_PANE_HEIGHT: u16 = 12; // Double-height sparklines like btop

#[derive(Debug, Clone, PartialEq)]
enum ConnectivityState {
    Checking,
    Connected,
    Disconnected,
    Intermittent,
}

#[derive(Debug, Clone)]
struct ConnectivityHistory {
    ipv4_results: VecDeque<(Instant, bool)>, // (timestamp, success)
    ipv6_results: VecDeque<(Instant, bool)>,
    ipv4_state: ConnectivityState,
    ipv6_state: ConnectivityState,
    last_state_change: Instant,
}

impl ConnectivityHistory {
    fn new() -> Self {
        Self {
            ipv4_results: VecDeque::new(),
            ipv6_results: VecDeque::new(),
            ipv4_state: ConnectivityState::Checking,
            ipv6_state: ConnectivityState::Checking,
            last_state_change: Instant::now(),
        }
    }

    fn add_result(&mut self, ipv4_success: Option<bool>, ipv6_success: Option<bool>) {
        let now = Instant::now();

        // Keep last 10 results for each protocol
        const MAX_HISTORY: usize = 10;

        if let Some(success) = ipv4_success {
            self.ipv4_results.push_back((now, success));
            while self.ipv4_results.len() > MAX_HISTORY {
                self.ipv4_results.pop_front();
            }
            self.update_ipv4_state();
        }

        if let Some(success) = ipv6_success {
            self.ipv6_results.push_back((now, success));
            while self.ipv6_results.len() > MAX_HISTORY {
                self.ipv6_results.pop_front();
            }
            self.update_ipv6_state();
        }
    }

    fn update_ipv4_state(&mut self) {
        let new_state = self.calculate_state(&self.ipv4_results);
        if new_state != self.ipv4_state {
            self.ipv4_state = new_state;
            self.last_state_change = Instant::now();
        }
    }

    fn update_ipv6_state(&mut self) {
        let new_state = self.calculate_state(&self.ipv6_results);
        if new_state != self.ipv6_state {
            self.ipv6_state = new_state;
            self.last_state_change = Instant::now();
        }
    }

    fn calculate_state(&self, results: &VecDeque<(Instant, bool)>) -> ConnectivityState {
        if results.is_empty() {
            return ConnectivityState::Checking;
        }

        let recent_count = results.len().min(5); // Look at last 5 results
        let recent_results: Vec<bool> = results.iter()
            .rev()
            .take(recent_count)
            .map(|(_, success)| *success)
            .collect();

        let success_count = recent_results.iter().filter(|&&s| s).count();
        let failure_count = recent_results.len() - success_count;

        match (success_count, failure_count) {
            (s, 0) if s >= 2 => ConnectivityState::Connected,     // All recent pings successful
            (0, f) if f >= 3 => ConnectivityState::Disconnected,  // Multiple recent failures
            (s, f) if s > 0 && f > 0 => ConnectivityState::Intermittent, // Mixed results
            _ => ConnectivityState::Checking, // Not enough data
        }
    }
}

/// CONNECTIVITY pane displays real-time ping latency and network connectivity metrics
pub struct ConnectivityPane {
    title: &'static str,
    id: &'static str,
    ipv4_sparkline: Mutex<SparklineData>,
    ipv6_sparkline: Mutex<SparklineData>,
    last_ping_timestamp: Mutex<Option<std::time::Instant>>,
    connectivity_history: Mutex<ConnectivityHistory>,
}

impl ConnectivityPane {
    pub fn new() -> Self {
        log::debug!("[tui::connectivity] new:");
        let pane = Self {
            title: "connectivity",
            id: "connectivity",
            ipv4_sparkline: Mutex::new(SparklineData::new(Some(200))), // Store more data for wider sparklines
            ipv6_sparkline: Mutex::new(SparklineData::new(Some(200))),
            last_ping_timestamp: Mutex::new(None),
            connectivity_history: Mutex::new(ConnectivityHistory::new()),
        };



        pane
    }

    fn update_sparklines(&self, ping_result: &crate::scan::ping::PingResult) {
        // Check if this is new data
        let is_new_data = if let Ok(mut last_timestamp) = self.last_ping_timestamp.lock() {
            let current_timestamp = ping_result.queried_at;
            match *last_timestamp {
                Some(last) if last >= current_timestamp => {
                    // This is old data, don't update sparklines
                    log::trace!("[tui::connectivity] skipping_old_data: last={:?} current={:?}", last, current_timestamp);
                    return;
                }
                _ => {
                    // This is new data, update timestamp and continue
                    log::debug!("[tui::connectivity] new_ping_data: timestamp={:?}", current_timestamp);
                    *last_timestamp = Some(current_timestamp);
                    true
                }
            }
        } else {
            log::warn!("[tui::connectivity] failed_to_lock_timestamp");
            false
        };

        if !is_new_data {
            return;
        }

        let ipv4_success = ping_result.ipv4_status.is_success();
        let ipv6_success = ping_result.ipv6_status.is_success();
        let ipv4_attempted = ping_result.ipv4_status.was_attempted();
        let ipv6_attempted = ping_result.ipv6_status.was_attempted();

        log::debug!("[tui::connectivity] updating_sparklines: ipv4_success={} ipv6_success={}",
            ipv4_success, ipv6_success);

        // Update connectivity history - treat any attempt as a result to track
        if let Ok(mut history) = self.connectivity_history.lock() {
            let ipv4_result = if ipv4_attempted {
                Some(ipv4_success)
            } else {
                None
            };
            let ipv6_result = if ipv6_attempted {
                Some(ipv6_success)
            } else {
                None
            };

            history.add_result(ipv4_result, ipv6_result);
            log::debug!("[tui::connectivity] connectivity_history_updated: ipv4_attempted={} ipv4_success={} ipv4_state={:?} ipv6_attempted={} ipv6_success={} ipv6_state={:?}",
                ipv4_attempted, ipv4_success, history.ipv4_state, ipv6_attempted, ipv6_success, history.ipv6_state);
        } else {
            log::warn!("[tui::connectivity] failed_to_lock_connectivity_history");
        }

        // Update IPv4 sparkline
        if let Some(latency) = ping_result.ipv4_status.latency() {
            if let Ok(mut sparkline) = self.ipv4_sparkline.lock() {
                sparkline.add_latency(latency);
                log::debug!("[tui::connectivity] ipv4_sparkline_updated: latency={}ms points={} min={:?} max={:?} avg={:?}",
                    latency.as_millis(), sparkline.len(), sparkline.min_value(), sparkline.max_value(), sparkline.average_value());
            } else {
                log::warn!("[tui::connectivity] failed_to_lock_ipv4_sparkline");
            }
        } else {
            log::debug!("[tui::connectivity] no_ipv4_latency: status={:?}", ping_result.ipv4_status);
        }

        // Update IPv6 sparkline
        log::debug!("[tui::connectivity] ipv6_ping_status_check: status={:?} was_attempted={} is_success={}",
            ping_result.ipv6_status, ipv6_attempted, ipv6_success);

        if let Some(latency) = ping_result.ipv6_status.latency() {
            if let Ok(mut sparkline) = self.ipv6_sparkline.lock() {
                sparkline.add_latency(latency);
                log::debug!("[tui::connectivity] ipv6_sparkline_updated: latency={}ms points={}",
                    latency.as_millis(), sparkline.len());
            } else {
                log::warn!("[tui::connectivity] failed_to_lock_ipv6_sparkline");
            }
        } else {
            log::debug!("[tui::connectivity] no_ipv6_latency: status={:?} attempted={}",
                ping_result.ipv6_status, ipv6_attempted);

            // Log detailed IPv6 status for debugging
            match &ping_result.ipv6_status {
                crate::scan::ping::PingStatus::Failed(msg) => {
                    log::debug!("[tui::connectivity] ipv6_ping_failed: error_msg={}", msg);
                }
                crate::scan::ping::PingStatus::NoAddress => {
                    log::debug!("[tui::connectivity] ipv6_ping_no_address");
                }
                crate::scan::ping::PingStatus::NotQueried => {
                    log::debug!("[tui::connectivity] ipv6_ping_not_queried");
                }
                crate::scan::ping::PingStatus::ToolMissing(tool) => {
                    log::debug!("[tui::connectivity] ipv6_ping_tool_missing: tool={}", tool);
                }
                _ => {
                    log::debug!("[tui::connectivity] ipv6_ping_other_status");
                }
            }
        }
    }
}

impl Default for ConnectivityPane {
    fn default() -> Self {
        Self::new()
    }
}

impl Pane for ConnectivityPane {
    fn render(&self, frame: &mut Frame, area: Rect, state: &AppState, focused: bool) {
        log::trace!("[tui::connectivity] render: area={}x{} focused={}",
            area.width, area.height, focused);

        let block = create_block(self.title, focused);

        // Calculate content area (inside the border)
        let inner_area = block.inner(area);

        // Render the block first
        block.render(area, frame.buffer_mut());

        // Prepare content lines
        let mut lines = Vec::new();

        // Get stable connectivity states to prevent flashing
        let (has_ipv4, has_ipv6, status_text, status_color) = if let Ok(history) = self.connectivity_history.lock() {
            let ipv4_connected = matches!(history.ipv4_state, ConnectivityState::Connected);
            let ipv6_connected = matches!(history.ipv6_state, ConnectivityState::Connected);

            let (text, color) = match (&history.ipv4_state, &history.ipv6_state) {
                (ConnectivityState::Connected, ConnectivityState::Connected) => ("dual-stack", Color::Green),
                (ConnectivityState::Connected, ConnectivityState::Disconnected) => ("ipv4 only", Color::Yellow),
                (ConnectivityState::Disconnected, ConnectivityState::Connected) => ("ipv6 only", Color::Yellow),
                (ConnectivityState::Connected, ConnectivityState::Intermittent) => ("ipv4 stable, ipv6 intermittent", Color::Yellow),
                (ConnectivityState::Intermittent, ConnectivityState::Connected) => ("ipv4 intermittent, ipv6 stable", Color::Yellow),
                (ConnectivityState::Intermittent, ConnectivityState::Intermittent) => ("intermittent connectivity", Color::Yellow),
                (ConnectivityState::Intermittent, ConnectivityState::Disconnected) => ("ipv4 intermittent", Color::Yellow),
                (ConnectivityState::Disconnected, ConnectivityState::Intermittent) => ("ipv6 intermittent", Color::Yellow),
                (ConnectivityState::Disconnected, ConnectivityState::Disconnected) => ("no connectivity", Color::Red),
                (ConnectivityState::Checking, _) | (_, ConnectivityState::Checking) => ("checking connectivity", Color::Gray),
            };

            log::trace!("[tui::connectivity] stable_states: ipv4={:?} ipv6={:?} text={}",
                history.ipv4_state, history.ipv6_state, text);

            (ipv4_connected, ipv6_connected, text, color)
        } else {
            log::warn!("[tui::connectivity] failed_to_lock_connectivity_history");
            (false, false, "checking", Color::Gray)
        };

        // Update sparklines if we have ping results
        if let Some(ping_state) = state.scanners.get("ping") {
            if let Some(ScanResult::Ping(ping)) = &ping_state.result {
                log::trace!("[tui::connectivity] updating_sparklines_from_render");
                self.update_sparklines(ping);
            }
        }

        // Status line
        lines.push(Line::from(vec![
            Span::styled("🌐 Status: ", Style::default().fg(Color::Cyan)),
            Span::styled(status_text, Style::default().fg(status_color)),
        ]));

        lines.push(Line::from(""));

        // Calculate sparkline width - use almost the full width of the pane
        let sparkline_width = (inner_area.width.saturating_sub(2)) as usize; // Leave 2 chars margin

        // Get sparkline data for native Ratatui Sparkline widgets
        let (ipv4_current, ipv4_avg, ipv4_data) = if let Ok(sparkline) = self.ipv4_sparkline.lock() {
            let current = sparkline.current_value().map(|v| format!("{}ms", v as u32)).unwrap_or_else(|| "---".to_string());
            let avg = sparkline.average_value().map(|v| format!("{}ms", v as u32)).unwrap_or_else(|| "---".to_string());
            let data = sparkline.get_data_for_width(sparkline_width);
            log::trace!("[tui::connectivity] ipv4_sparkline_render: points={} width={} data_len={} current={} avg={}",
                sparkline.len(), sparkline_width, data.len(), current, avg);
            (current, avg, data)
        } else {
            log::trace!("[tui::connectivity] ipv4_sparkline_lock_failed");
            ("---".to_string(), "---".to_string(), vec![])
        };

        let (ipv6_current, ipv6_avg, ipv6_data) = if let Ok(sparkline) = self.ipv6_sparkline.lock() {
            let current = sparkline.current_value().map(|v| format!("{}ms", v as u32)).unwrap_or_else(|| "---".to_string());
            let avg = sparkline.average_value().map(|v| format!("{}ms", v as u32)).unwrap_or_else(|| "---".to_string());
            let data = sparkline.get_data_for_width(sparkline_width);
            log::trace!("[tui::connectivity] ipv6_sparkline_render: points={} width={} data_len={} current={} avg={}",
                sparkline.len(), sparkline_width, data.len(), current, avg);
            (current, avg, data)
        } else {
            log::trace!("[tui::connectivity] ipv6_sparkline_lock_failed");
            ("---".to_string(), "---".to_string(), vec![])
        };

        // Create layout for status and sparklines
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1), // Status line
                Constraint::Length(1), // Spacing
                Constraint::Length(1), // IPv4 title
                Constraint::Length(4), // IPv4 sparkline (taller for btop-style)
                Constraint::Length(1), // Spacing
                Constraint::Length(1), // IPv6 title
                Constraint::Length(4), // IPv6 sparkline (taller for btop-style)
            ])
            .split(inner_area);

        // Render status paragraph
        let status_paragraph = Paragraph::new(lines)
            .alignment(Alignment::Left);
        status_paragraph.render(chunks[0], frame.buffer_mut());

        // IPv4 section - use connectivity state for consistent display
        let ipv4_status_text = if let Ok(history) = self.connectivity_history.lock() {
            match history.ipv4_state {
                ConnectivityState::Connected => format!("{} avg:{}", ipv4_current, ipv4_avg),
                ConnectivityState::Disconnected => "disconnected".to_string(),
                ConnectivityState::Intermittent => format!("intermittent {} avg:{}", ipv4_current, ipv4_avg),
                ConnectivityState::Checking => "checking".to_string(),
            }
        } else {
            format!("{} avg:{}", ipv4_current, ipv4_avg)
        };

        let ipv4_title = Paragraph::new(Line::from(vec![
            Span::styled("📡 IPv4: ", Style::default().fg(Color::White)),
            Span::styled(ipv4_status_text, Style::default().fg(if has_ipv4 { Color::Green } else { Color::Red })),
        ]));
        ipv4_title.render(chunks[2], frame.buffer_mut());

        // IPv4 Sparkline
        let ipv4_color = if has_ipv4 {
            if ipv4_data.iter().any(|&v| v > 0) {
                let avg = ipv4_data.iter().sum::<u64>() as f64 / ipv4_data.len() as f64;
                if avg <= 50.0 {
                    Color::Green
                } else if avg <= 150.0 {
                    Color::Yellow
                } else {
                    Color::Red
                }
            } else {
                Color::Green
            }
        } else {
            Color::Red
        };

        let ipv4_sparkline = Sparkline::default()
            .data(&ipv4_data)
            .style(Style::default().fg(ipv4_color));
        ipv4_sparkline.render(chunks[3], frame.buffer_mut());

        // IPv6 section - use connectivity state for consistent display
        let ipv6_status_text = if let Ok(history) = self.connectivity_history.lock() {
            match history.ipv6_state {
                ConnectivityState::Connected => format!("{} avg:{}", ipv6_current, ipv6_avg),
                ConnectivityState::Disconnected => "network unreachable".to_string(),
                ConnectivityState::Intermittent => format!("intermittent {} avg:{}", ipv6_current, ipv6_avg),
                ConnectivityState::Checking => "checking".to_string(),
            }
        } else {
            format!("{} avg:{}", ipv6_current, ipv6_avg)
        };

        let ipv6_title = Paragraph::new(Line::from(vec![
            Span::styled("📡 IPv6: ", Style::default().fg(Color::White)),
            Span::styled(ipv6_status_text, Style::default().fg(if has_ipv6 { Color::Green } else { Color::Red })),
        ]));
        ipv6_title.render(chunks[5], frame.buffer_mut());

        // IPv6 Sparkline
        let ipv6_color = if has_ipv6 {
            if ipv6_data.iter().any(|&v| v > 0) {
                let avg = ipv6_data.iter().sum::<u64>() as f64 / ipv6_data.len() as f64;
                if avg <= 50.0 {
                    Color::Green
                } else if avg <= 150.0 {
                    Color::Yellow
                } else {
                    Color::Red
                }
            } else {
                Color::Green
            }
        } else {
            Color::Red
        };

        let ipv6_sparkline = Sparkline::default()
            .data(&ipv6_data)
            .style(Style::default().fg(ipv6_color));
        ipv6_sparkline.render(chunks[6], frame.buffer_mut());
    }

    fn title(&self) -> &'static str {
        self.title
    }

    fn id(&self) -> &'static str {
        self.id
    }

    fn min_size(&self) -> (u16, u16) {
        (MIN_CONNECTIVITY_PANE_WIDTH, MIN_CONNECTIVITY_PANE_HEIGHT)
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn is_focusable(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_connectivity_pane_creation() {
        let pane = ConnectivityPane::new();
        assert_eq!(pane.title(), "connectivity");
        assert_eq!(pane.id(), "connectivity");
        assert_eq!(pane.min_size(), (MIN_CONNECTIVITY_PANE_WIDTH, MIN_CONNECTIVITY_PANE_HEIGHT));
        assert!(pane.is_visible());
        assert!(pane.is_focusable());
    }

    #[test]
    fn test_sparkline_data_updates() {
        let pane = ConnectivityPane::new();

        // Add some test data to IPv4 sparkline
        {
            let mut sparkline = pane.ipv4_sparkline.lock().expect("Failed to lock sparkline in test");
            sparkline.add_latency(Duration::from_millis(25));
            sparkline.add_latency(Duration::from_millis(30));
            sparkline.add_latency(Duration::from_millis(20));
            assert_eq!(sparkline.len(), 3); // 3 real points
            assert!(sparkline.current_value().is_some());
            assert!(sparkline.average_value().is_some());
        }

        // Test sparkline data extraction
        {
            let sparkline = pane.ipv4_sparkline.lock().expect("Failed to lock sparkline in test");
            let data = sparkline.get_data_for_width(50);
            assert!(!data.is_empty());
            assert_eq!(data.len(), 3); // Should have 3 data points as added above
        }
    }
}
