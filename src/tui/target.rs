use crate::tui::pane::{create_block, Pane};
use crate::types::{AppState, ScanStatus};
use ratatui::{
    layout::{Alignment, Rect},
    style::{Color, Style},
    text::{Line, Span},
    widgets::{Paragraph, Widget},
    Frame,
};

/// TARGET pane displays basic target information and scanner status overview
pub struct TargetPane {
    title: &'static str,
    id: &'static str,
}

impl TargetPane {
    pub fn new() -> Self {
        Self {
            title: "target",
            id: "target",
        }
    }
    
    /// Format elapsed time in a human-readable way
    fn format_elapsed(elapsed: std::time::Duration) -> String {
        let secs = elapsed.as_secs();
        if secs < 60 {
            format!("{}s", secs)
        } else if secs < 3600 {
            format!("{}m {}s", secs / 60, secs % 60)
        } else {
            format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
        }
    }
    
    /// Get status icon and color for a scanner status
    fn status_icon_and_color(status: &ScanStatus) -> (&'static str, Color) {
        match status {
            ScanStatus::Running => ("🔄", Color::Yellow),
            ScanStatus::Complete => ("✅", Color::Green),
            ScanStatus::Failed => ("❌", Color::Red),
        }
    }
    
    /// Calculate scanner statistics
    fn calculate_stats(state: &AppState) -> (usize, usize, usize, usize) {
        let total = state.scanners.len();
        let mut running = 0;
        let mut complete = 0;
        let mut failed = 0;
        
        for scanner in state.scanners.iter() {
            match scanner.status {
                ScanStatus::Running => running += 1,
                ScanStatus::Complete => complete += 1,
                ScanStatus::Failed => failed += 1,
            }
        }
        
        (total, running, complete, failed)
    }
}

impl Default for TargetPane {
    fn default() -> Self {
        Self::new()
    }
}

impl Pane for TargetPane {
    fn render(&self, frame: &mut Frame, area: Rect, state: &AppState) {
        let focused = false; // TODO: Get from layout focus state
        let block = create_block(self.title, focused);
        
        // Calculate content area (inside the border)
        let inner_area = block.inner(area);
        
        // Render the block first
        block.render(area, frame.buffer_mut());
        
        // Prepare content lines
        let mut lines = Vec::new();
        
        // Target information
        lines.push(Line::from(vec![
            Span::styled("🎯 ", Style::default().fg(Color::Cyan)),
            Span::styled(&state.target, Style::default().fg(Color::White)),
        ]));
        
        // TODO: Add resolved IP when available from DNS scanner
        // For now, show placeholder
        lines.push(Line::from(vec![
            Span::styled("📍 ", Style::default().fg(Color::Blue)),
            Span::styled("Resolving...", Style::default().fg(Color::Gray)),
        ]));
        
        // Empty line for spacing
        lines.push(Line::from(""));
        
        // Scanner statistics
        let (total, running, complete, failed) = Self::calculate_stats(state);
        
        lines.push(Line::from(vec![
            Span::styled("Status: ", Style::default().fg(Color::White)),
            Span::styled(
                format!("{}/{} scanners", complete, total),
                if failed > 0 {
                    Style::default().fg(Color::Red)
                } else if running > 0 {
                    Style::default().fg(Color::Yellow)
                } else {
                    Style::default().fg(Color::Green)
                }
            ),
        ]));
        
        // Individual scanner status (show first few)
        let mut scanner_count = 0;
        for scanner in state.scanners.iter() {
            if scanner_count >= 3 { // Limit to 3 scanners to fit in pane
                break;
            }
            
            let (icon, color) = Self::status_icon_and_color(&scanner.status);
            let elapsed = scanner.last_updated.elapsed();
            
            lines.push(Line::from(vec![
                Span::styled(format!("{} ", icon), Style::default().fg(color)),
                Span::styled(
                    format!("{}: ", scanner.key().to_uppercase()),
                    Style::default().fg(Color::White)
                ),
                Span::styled(
                    Self::format_elapsed(elapsed),
                    Style::default().fg(Color::Gray)
                ),
            ]));
            
            scanner_count += 1;
        }
        
        // Show "and X more" if there are more scanners
        if state.scanners.len() > 3 {
            let remaining = state.scanners.len() - 3;
            lines.push(Line::from(vec![
                Span::styled(
                    format!("   ... and {} more", remaining),
                    Style::default().fg(Color::Gray)
                ),
            ]));
        }
        
        // Create and render the paragraph
        let paragraph = Paragraph::new(lines)
            .alignment(Alignment::Left);
        
        paragraph.render(inner_area, frame.buffer_mut());
    }
    
    fn title(&self) -> &'static str {
        self.title
    }
    
    fn id(&self) -> &'static str {
        self.id
    }
    
    fn min_size(&self) -> (u16, u16) {
        (25, 8) // Slightly larger to accommodate content
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ScanState, ScanStatus};
    use dashmap::DashMap;
    use std::time::Instant;
    
    #[test]
    fn test_target_pane_creation() {
        let pane = TargetPane::new();
        assert_eq!(pane.title(), "target");
        assert_eq!(pane.id(), "target");
        assert_eq!(pane.min_size(), (25, 8));
        assert!(pane.is_visible());
        assert!(!pane.is_focusable());
    }
    
    #[test]
    fn test_format_elapsed() {
        use std::time::Duration;
        
        assert_eq!(TargetPane::format_elapsed(Duration::from_secs(30)), "30s");
        assert_eq!(TargetPane::format_elapsed(Duration::from_secs(90)), "1m 30s");
        assert_eq!(TargetPane::format_elapsed(Duration::from_secs(3661)), "1h 1m");
    }
    
    #[test]
    fn test_status_icon_and_color() {
        let (icon, color) = TargetPane::status_icon_and_color(&ScanStatus::Running);
        assert_eq!(icon, "🔄");
        assert_eq!(color, Color::Yellow);
        
        let (icon, color) = TargetPane::status_icon_and_color(&ScanStatus::Complete);
        assert_eq!(icon, "✅");
        assert_eq!(color, Color::Green);
        
        let (icon, color) = TargetPane::status_icon_and_color(&ScanStatus::Failed);
        assert_eq!(icon, "❌");
        assert_eq!(color, Color::Red);
    }
    
    #[test]
    fn test_calculate_stats() {
        let state = AppState {
            target: "example.com".to_string(),
            scanners: DashMap::new(),
        };
        
        // Add some test scanner states
        state.scanners.insert("ping".to_string(), ScanState {
            result: None,
            error: None,
            status: ScanStatus::Complete,
            last_updated: Instant::now(),
            history: Default::default(),
        });
        
        state.scanners.insert("dns".to_string(), ScanState {
            result: None,
            error: None,
            status: ScanStatus::Running,
            last_updated: Instant::now(),
            history: Default::default(),
        });
        
        state.scanners.insert("http".to_string(), ScanState {
            result: None,
            error: Some(eyre::eyre!("Connection failed")),
            status: ScanStatus::Failed,
            last_updated: Instant::now(),
            history: Default::default(),
        });
        
        let (total, running, complete, failed) = TargetPane::calculate_stats(&state);
        assert_eq!(total, 3);
        assert_eq!(running, 1);
        assert_eq!(complete, 1);
        assert_eq!(failed, 1);
    }
} 