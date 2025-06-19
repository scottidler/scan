use std::collections::VecDeque;
use std::time::{Duration, Instant};
use ratatui::{
    style::{Color, Style},
    text::Span,
};

const MAX_SPARKLINE_POINTS: usize = 40;
// btop-style Braille patterns for ultra-smooth sparklines (like btop's "braille" mode)
// Braille patterns give us 8 vertical levels per character (2x4 dot matrix)
const SPARKLINE_CHARS: [char; 9] = [
    ' ',   // 0/8 - empty
    '⠁',   // 1/8 - bottom dot
    '⠃',   // 2/8 - bottom two dots
    '⠇',   // 3/8 - bottom three dots
    '⠏',   // 4/8 - bottom four dots (half height)
    '⠟',   // 5/8 - bottom five dots
    '⠿',   // 6/8 - bottom six dots
    '⡿',   // 7/8 - bottom seven dots
    '⣿',   // 8/8 - full Braille block (all 8 dots)
];

#[derive(Debug, Clone)]
pub struct DataPoint {
    pub value: f64,
    pub timestamp: Instant,
}

#[derive(Debug, Clone)]
pub struct SparklineData {
    points: VecDeque<DataPoint>,
    max_points: usize,
    min_value: f64,
    max_value: f64,
}

impl SparklineData {
    pub fn new(max_points: Option<usize>) -> Self {
        Self {
            points: VecDeque::new(),
            max_points: max_points.unwrap_or(MAX_SPARKLINE_POINTS),
            min_value: f64::INFINITY,
            max_value: f64::NEG_INFINITY,
        }
    }

    pub fn add_point(&mut self, value: f64) {
        let point = DataPoint {
            value,
            timestamp: Instant::now(),
        };

        self.points.push_back(point);

        // Remove old points if we exceed max_points
        while self.points.len() > self.max_points {
            self.points.pop_front();
        }

        // Update min/max values
        self.update_bounds();
    }

    pub fn add_latency(&mut self, latency: Duration) {
        self.add_point(latency.as_millis() as f64);
    }

    fn update_bounds(&mut self) {
        if self.points.is_empty() {
            self.min_value = f64::INFINITY;
            self.max_value = f64::NEG_INFINITY;
            return;
        }

        self.min_value = self.points.iter().map(|p| p.value).fold(f64::INFINITY, f64::min);
        self.max_value = self.points.iter().map(|p| p.value).fold(f64::NEG_INFINITY, f64::max);
    }

    // Get bounds optimized for latency visualization (always start from 0)
    fn get_latency_bounds(&self) -> (f64, f64) {
        if self.points.is_empty() {
            return (0.0, 1.0);
        }

        let raw_max = self.points.iter().map(|p| p.value).fold(f64::NEG_INFINITY, f64::max);
        let raw_min = self.points.iter().map(|p| p.value).fold(f64::INFINITY, f64::min);

        // For latency, always start from 0 for better relative performance visualization
        let min_value = 0.0;

        // Add some padding to the max for better visual scaling
        let range = raw_max - raw_min;
        let max_value = if range > 0.0 {
            // Add 10% padding to show variations better
            raw_max + (range * 0.1)
        } else {
            // Ensure we have some range for single values
            raw_max.max(1.0) * 1.2
        };

        (min_value, max_value)
    }

    pub fn render_sparkline(&self, width: usize) -> String {
        if self.points.is_empty() || width == 0 {
            return " ".repeat(width);
        }

        let mut result = String::with_capacity(width);
        let range = self.max_value - self.min_value;

        for i in 0..width {
            let point_index = if self.points.len() <= width {
                // Not enough points to fill width, use what we have
                if i < self.points.len() {
                    i
                } else {
                    // Fill remaining with spaces
                    result.push(' ');
                    continue;
                }
            } else {
                // More points than width, sample from the end
                let start_index = self.points.len() - width;
                start_index + i
            };

            if point_index < self.points.len() {
                let value = self.points[point_index].value;
                let normalized = if range > 0.0 {
                    ((value - self.min_value) / range).clamp(0.0, 1.0)
                } else {
                    0.5
                };

                let char_index = (normalized * (SPARKLINE_CHARS.len() - 1) as f64).round() as usize;
                result.push(SPARKLINE_CHARS[char_index.min(SPARKLINE_CHARS.len() - 1)]);
            } else {
                result.push(' ');
            }
        }

        result
    }

    pub fn render_colored_sparkline(&self, width: usize, good_threshold: f64, warning_threshold: f64) -> Vec<Span<'static>> {
        if self.points.is_empty() || width == 0 {
            return vec![Span::styled(" ".repeat(width), Style::default().fg(Color::Gray))];
        }

        let mut spans = Vec::new();
        let range = self.max_value - self.min_value;

        for i in 0..width {
            let point_index = if self.points.len() <= width {
                if i < self.points.len() {
                    i
                } else {
                    spans.push(Span::styled(" ".to_string(), Style::default().fg(Color::Gray)));
                    continue;
                }
            } else {
                let start_index = self.points.len() - width;
                start_index + i
            };

            if point_index < self.points.len() {
                let value = self.points[point_index].value;
                let normalized = if range > 0.0 {
                    ((value - self.min_value) / range).clamp(0.0, 1.0)
                } else {
                    0.5
                };

                let char_index = (normalized * (SPARKLINE_CHARS.len() - 1) as f64).round() as usize;
                let char = SPARKLINE_CHARS[char_index.min(SPARKLINE_CHARS.len() - 1)];

                // btop-style color gradient based on value thresholds
                let color = if value <= good_threshold {
                    // Green zone - excellent performance
                    if value <= good_threshold * 0.5 {
                        Color::Rgb(0, 255, 0)   // Bright green for very low latency
                    } else {
                        Color::Rgb(50, 205, 50) // Light green
                    }
                } else if value <= warning_threshold {
                    // Yellow zone - moderate performance
                    let ratio = (value - good_threshold) / (warning_threshold - good_threshold);
                    if ratio < 0.5 {
                        Color::Rgb(154, 205, 50)  // Yellow-green
                    } else {
                        Color::Rgb(255, 215, 0)   // Gold/yellow
                    }
                } else {
                    // Red zone - poor performance
                    let ratio = ((value - warning_threshold) / warning_threshold).min(1.0);
                    if ratio < 0.5 {
                        Color::Rgb(255, 140, 0)   // Orange-red
                    } else {
                        Color::Rgb(220, 20, 60)   // Crimson for very high latency
                    }
                };

                spans.push(Span::styled(char.to_string(), Style::default().fg(color)));
            } else {
                spans.push(Span::styled(" ".to_string(), Style::default().fg(Color::Gray)));
            }
        }

        spans
    }

    /// Render multi-height sparkline like btop (creates proper stacked graph visualization)
    pub fn render_multi_height_sparkline(&self, width: usize, height: usize, good_threshold: f64, warning_threshold: f64) -> Vec<Vec<Span<'static>>> {
        if self.points.is_empty() || width == 0 || height == 0 {
            let empty_line = vec![Span::styled(" ".repeat(width), Style::default().fg(Color::Gray))];
            return vec![empty_line; height];
        }

        let mut result = Vec::new();

        // Use latency-optimized bounds for better visualization
        let (min_value, max_value) = self.get_latency_bounds();
        let range = max_value - min_value;

        // Total vertical resolution = height * 8 (8 Braille levels per row)
        let total_levels = height * 8;

        // Create height number of rows, top to bottom
        for row in 0..height {
            let mut row_spans = Vec::new();

            for i in 0..width {
                let point_index = if self.points.len() <= width {
                    if i < self.points.len() {
                        i
                    } else {
                        row_spans.push(Span::styled(" ".to_string(), Style::default().fg(Color::Gray)));
                        continue;
                    }
                } else {
                    let start_index = self.points.len() - width;
                    start_index + i
                };

                if point_index < self.points.len() {
                    let value = self.points[point_index].value;
                    let normalized = if range > 0.0 {
                        ((value - min_value) / range).clamp(0.0, 1.0)
                    } else {
                        0.5
                    };

                    // Calculate total height in levels (0 to total_levels)
                    let value_levels = (normalized * total_levels as f64).round() as usize;

                    // Current row's level range (top row = highest levels)
                    let row_top_level = total_levels - (row * 8);
                    let row_bottom_level = row_top_level.saturating_sub(8);

                    // Determine what to show in this row
                    let char_to_show = if value_levels >= row_top_level {
                        // Full block - value extends above this row
                        SPARKLINE_CHARS[8]
                    } else if value_levels > row_bottom_level {
                        // Partial block - value ends in this row
                        let levels_in_row = value_levels - row_bottom_level;
                        SPARKLINE_CHARS[levels_in_row.min(8)]
                    } else {
                        // Empty - value doesn't reach this row
                        ' '
                    };

                    // btop-style color gradient
                    let color = if value <= good_threshold {
                        if value <= good_threshold * 0.5 {
                            Color::Rgb(0, 255, 0)   // Bright green
                        } else {
                            Color::Rgb(50, 205, 50) // Light green
                        }
                    } else if value <= warning_threshold {
                        let ratio = (value - good_threshold) / (warning_threshold - good_threshold);
                        if ratio < 0.5 {
                            Color::Rgb(154, 205, 50)  // Yellow-green
                        } else {
                            Color::Rgb(255, 215, 0)   // Gold
                        }
                    } else {
                        let ratio = ((value - warning_threshold) / warning_threshold).min(1.0);
                        if ratio < 0.5 {
                            Color::Rgb(255, 140, 0)   // Orange-red
                        } else {
                            Color::Rgb(220, 20, 60)   // Crimson
                        }
                    };

                    row_spans.push(Span::styled(char_to_show.to_string(), Style::default().fg(color)));
                } else {
                    row_spans.push(Span::styled(" ".to_string(), Style::default().fg(Color::Gray)));
                }
            }

            result.push(row_spans);
        }

        result
    }

    /// Render double-height sparkline (compatibility wrapper for 2-row version)
    pub fn render_double_height_sparkline(&self, width: usize, good_threshold: f64, warning_threshold: f64) -> (Vec<Span<'static>>, Vec<Span<'static>>) {
        let rows = self.render_multi_height_sparkline(width, 2, good_threshold, warning_threshold);
        if rows.len() >= 2 {
            (rows[0].clone(), rows[1].clone())
        } else {
            let empty_line = vec![Span::styled(" ".repeat(width), Style::default().fg(Color::Gray))];
            (empty_line.clone(), empty_line)
        }
    }

    pub fn current_value(&self) -> Option<f64> {
        self.points.back().map(|p| p.value)
    }

    pub fn average_value(&self) -> Option<f64> {
        if self.points.is_empty() {
            return None;
        }

        let sum: f64 = self.points.iter().map(|p| p.value).sum();
        Some(sum / self.points.len() as f64)
    }

    pub fn min_value(&self) -> Option<f64> {
        if self.points.is_empty() {
            None
        } else {
            Some(self.min_value)
        }
    }

    pub fn max_value(&self) -> Option<f64> {
        if self.points.is_empty() {
            None
        } else {
            Some(self.max_value)
        }
    }

    pub fn is_empty(&self) -> bool {
        self.points.is_empty()
    }

    pub fn len(&self) -> usize {
        self.points.len()
    }

    /// Get raw data values for use with Ratatui's native Sparkline widget
    /// Returns data in chronological order (oldest to newest, so newest appears on right)
    pub fn get_data(&self) -> Vec<u64> {
        self.points.iter().map(|p| p.value as u64).collect()
    }

    /// Get data sized to fit the given width, with newest data on the right
    pub fn get_data_for_width(&self, width: usize) -> Vec<u64> {
        if self.points.is_empty() {
            return vec![];
        }

        if self.points.len() <= width {
            // Not enough data to fill width, return what we have
            self.points.iter().map(|p| p.value as u64).collect()
        } else {
            // Take the most recent `width` points
            self.points.iter()
                .rev()
                .take(width)
                .rev()
                .map(|p| p.value as u64)
                .collect()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sparkline_creation() {
        let sparkline = SparklineData::new(None);
        assert!(sparkline.is_empty());
        assert_eq!(sparkline.len(), 0);
    }

    #[test]
    fn test_add_points() {
        let mut sparkline = SparklineData::new(Some(5));

        sparkline.add_point(10.0);
        sparkline.add_point(20.0);
        sparkline.add_point(15.0);

        assert_eq!(sparkline.len(), 3);
        assert_eq!(sparkline.current_value(), Some(15.0));
        assert_eq!(sparkline.min_value(), Some(10.0));
        assert_eq!(sparkline.max_value(), Some(20.0));
    }

    #[test]
    fn test_max_points_limit() {
        let mut sparkline = SparklineData::new(Some(3));

        for i in 0..5 {
            sparkline.add_point(i as f64);
        }

        assert_eq!(sparkline.len(), 3);
        assert_eq!(sparkline.current_value(), Some(4.0));
    }

    #[test]
    fn test_render_sparkline() {
        let mut sparkline = SparklineData::new(Some(10));

        sparkline.add_point(0.0);
        sparkline.add_point(50.0);
        sparkline.add_point(100.0);

        let rendered = sparkline.render_sparkline(5);
        assert_eq!(rendered.chars().count(), 5);
    }

    #[test]
    fn test_latency_addition() {
        let mut sparkline = SparklineData::new(Some(5));

        sparkline.add_latency(Duration::from_millis(50));
        sparkline.add_latency(Duration::from_millis(100));

        assert_eq!(sparkline.len(), 2);
        assert_eq!(sparkline.current_value(), Some(100.0));
    }
}