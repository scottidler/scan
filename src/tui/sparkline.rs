use std::collections::VecDeque;
use std::time::{Duration, Instant};

const MAX_SPARKLINE_POINTS: usize = 40;

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
    fn test_get_data_for_width() {
        let mut sparkline = SparklineData::new(Some(10));

        sparkline.add_point(10.0);
        sparkline.add_point(20.0);
        sparkline.add_point(30.0);

        let data = sparkline.get_data_for_width(5);
        assert_eq!(data, vec![10, 20, 30]);

        let data = sparkline.get_data_for_width(2);
        assert_eq!(data, vec![20, 30]); // Should get most recent 2
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