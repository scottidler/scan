//! Ping latency history for the connectivity sparklines, and the pure math that turns a visible
//! window of it into bars: the stepped scale, the sub-row floor, and newest-first order.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Scale ceilings in ms. 5000 is the ping timeout (`scan/ping.rs`), so no reply exceeds it.
const SCALE_STEPS_MS: [u64; 12] = [1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000];
const MICROS_PER_MS: u64 = 1000;
/// ratatui draws a bar `value * rows * 8 / max` eighths tall.
const EIGHTHS_PER_ROW: u64 = 8;

/// One ping cycle: when it ran, and its round trip in µs, `None` when the ping failed.
pub type Sample = (Instant, Option<u64>);

#[derive(Debug, Clone)]
pub struct SparklineData {
    samples: VecDeque<Sample>,
    capacity: usize,
}

impl SparklineData {
    pub fn new(capacity: usize) -> Self {
        Self {
            samples: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    /// Record one ping cycle at `at`; `None` records a failed ping, which keeps its slot on the time axis.
    pub fn add_sample(&mut self, at: Instant, latency: Option<Duration>) {
        let micros = latency.map(|latency| u64::try_from(latency.as_micros()).unwrap_or(u64::MAX));
        self.samples.push_back((at, micros));
        while self.samples.len() > self.capacity {
            self.samples.pop_front();
        }
    }

    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    pub fn len(&self) -> usize {
        self.samples.len()
    }

    /// The latest sample's latency in µs: `None` with no samples, `Some(None)` when it failed.
    pub fn latest(&self) -> Option<Option<u64>> {
        self.samples.back().map(|(_, micros)| *micros)
    }

    /// The newest `width` samples, oldest first.
    pub fn visible(&self, width: usize) -> Vec<Sample> {
        let skip = self.samples.len().saturating_sub(width);
        self.samples.iter().skip(skip).copied().collect()
    }
}

/// Mean of the successful samples in µs, `None` when none succeeded.
pub fn average_us(samples: &[Sample]) -> Option<u64> {
    let replies: Vec<u64> = samples.iter().filter_map(|(_, micros)| *micros).collect();
    if replies.is_empty() {
        return None;
    }
    Some(replies.iter().sum::<u64>() / replies.len() as u64)
}

/// The smallest scale step at or above the largest successful sample, in µs. 1ms when none succeeded.
pub fn scale_max_us(samples: &[Sample]) -> u64 {
    let peak = samples.iter().filter_map(|(_, micros)| *micros).max().unwrap_or(0);
    let step_ms = SCALE_STEPS_MS
        .iter()
        .copied()
        .find(|step| step * MICROS_PER_MS >= peak)
        .unwrap_or(SCALE_STEPS_MS[SCALE_STEPS_MS.len() - 1]);
    step_ms * MICROS_PER_MS
}

/// Time from the oldest to the newest sample; a failed cycle can take the full ping timeout, so
/// the span is measured, not derived from the sample count.
pub fn span(samples: &[Sample]) -> Duration {
    match (samples.first(), samples.last()) {
        (Some((oldest, _)), Some((newest, _))) => newest.saturating_duration_since(*oldest),
        _ => Duration::ZERO,
    }
}

/// Bar values for a `RightToLeft` sparkline `rows` tall at scale `max_us`: newest first, so the
/// newest bar is at the right edge. A reply too small to draw is raised to one eighth of a row.
pub fn bars_newest_first(samples: &[Sample], rows: u16, max_us: u64) -> Vec<Option<u64>> {
    let eighths = u64::from(rows) * EIGHTHS_PER_ROW;
    let smallest_visible = if eighths == 0 { 0 } else { max_us.div_ceil(eighths) };
    samples
        .iter()
        .rev()
        .map(|(_, micros)| micros.map(|value| value.max(smallest_visible)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{
        Terminal,
        backend::TestBackend,
        widgets::{RenderDirection, Sparkline},
    };

    fn samples(values: &[Option<u64>]) -> Vec<Sample> {
        let start = Instant::now();
        values
            .iter()
            .enumerate()
            .map(|(i, micros)| (start + Duration::from_secs(i as u64), *micros))
            .collect()
    }

    /// The glyphs a one-row `RightToLeft` sparkline draws for `data`, left to right.
    fn draw_one_row(data: &[Option<u64>], width: u16, max_us: u64) -> String {
        let mut terminal = Terminal::new(TestBackend::new(width, 1)).expect("TestBackend terminal");
        terminal
            .draw(|frame| {
                let sparkline = Sparkline::default()
                    .data(data)
                    .max(max_us)
                    .direction(RenderDirection::RightToLeft)
                    .absent_value_symbol("░");
                frame.render_widget(sparkline, frame.area());
            })
            .expect("draw sparkline");
        let buffer = terminal.backend().buffer();
        (0..width).map(|x| buffer[(x, 0)].symbol().to_string()).collect()
    }

    #[test]
    fn samples_are_stored_in_microseconds() {
        let mut data = SparklineData::new(5);
        data.add_sample(Instant::now(), Some(Duration::from_micros(500)));
        assert_eq!(data.latest(), Some(Some(500)));
    }

    #[test]
    fn a_failed_ping_is_recorded_not_dropped() {
        let mut data = SparklineData::new(5);
        data.add_sample(Instant::now(), Some(Duration::from_millis(12)));
        data.add_sample(Instant::now(), None);
        assert_eq!(data.len(), 2);
        assert_eq!(data.latest(), Some(None));
    }

    #[test]
    fn capacity_drops_the_oldest_sample() {
        let mut data = SparklineData::new(3);
        for ms in 1..=5 {
            data.add_sample(Instant::now(), Some(Duration::from_millis(ms)));
        }
        assert_eq!(data.len(), 3);
        let kept: Vec<Option<u64>> = data.visible(10).iter().map(|(_, micros)| *micros).collect();
        assert_eq!(kept, vec![Some(3000), Some(4000), Some(5000)]);
    }

    #[test]
    fn visible_is_the_newest_width_samples_oldest_first() {
        let mut data = SparklineData::new(10);
        for ms in 1..=4 {
            data.add_sample(Instant::now(), Some(Duration::from_millis(ms)));
        }
        let shown: Vec<Option<u64>> = data.visible(2).iter().map(|(_, micros)| *micros).collect();
        assert_eq!(shown, vec![Some(3000), Some(4000)]);
        assert!(SparklineData::new(3).visible(5).is_empty());
    }

    #[test]
    fn scale_is_the_smallest_step_at_or_above_the_peak() {
        assert_eq!(scale_max_us(&samples(&[Some(12_000), Some(9_000)])), 20_000);
        assert_eq!(scale_max_us(&samples(&[Some(20_000)])), 20_000);
        assert_eq!(scale_max_us(&samples(&[Some(500)])), 1_000);
        assert_eq!(scale_max_us(&samples(&[Some(1_200_000)])), 2_000_000);
        assert_eq!(scale_max_us(&samples(&[Some(4_999_000)])), 5_000_000);
    }

    #[test]
    fn scale_without_a_reply_is_one_millisecond() {
        assert_eq!(scale_max_us(&samples(&[None, None])), 1_000);
        assert_eq!(scale_max_us(&[]), 1_000);
    }

    #[test]
    fn average_counts_replies_only() {
        assert_eq!(average_us(&samples(&[Some(10_000), None, Some(20_000)])), Some(15_000));
        assert_eq!(average_us(&samples(&[None])), None);
    }

    #[test]
    fn span_runs_from_the_oldest_to_the_newest_timestamp() {
        assert_eq!(span(&samples(&[Some(1), None, Some(1)])), Duration::from_secs(2));
        assert_eq!(span(&[]), Duration::ZERO);
    }

    #[test]
    fn bars_are_newest_first_and_keep_failures_absent() {
        let bars = bars_newest_first(&samples(&[Some(1_000), None, Some(3_000)]), 1, 5_000);
        assert_eq!(bars, vec![Some(3_000), None, Some(1_000)]);
    }

    #[test]
    fn a_reply_too_small_to_draw_is_raised_to_one_eighth_of_a_row() {
        // 50µs at 1ms in one row is 50 * 8 / 1000 = 0 eighths: blank without the floor.
        assert_eq!(bars_newest_first(&samples(&[Some(50)]), 1, 1_000), vec![Some(125)]);
        assert_eq!(bars_newest_first(&samples(&[Some(0)]), 2, 1_000), vec![Some(63)]);
        assert_eq!(bars_newest_first(&samples(&[Some(800)]), 1, 1_000), vec![Some(800)]);
        let drawn = draw_one_row(&bars_newest_first(&samples(&[Some(50)]), 1, 1_000), 1, 1_000);
        assert_eq!(drawn, "▁");
    }

    #[test]
    fn half_millisecond_reply_at_one_millisecond_scale_draws_a_bar() {
        let mut data = SparklineData::new(5);
        data.add_sample(Instant::now(), Some(Duration::from_micros(500)));
        let visible = data.visible(1);
        let drawn = draw_one_row(&bars_newest_first(&visible, 1, scale_max_us(&visible)), 1, 1_000);
        // 500 * 8 / 1000 = 4 eighths. A ms-truncated 0 would show only the floor's one eighth.
        assert_eq!(drawn, "▄", "500µs at max 1ms is not a half-row bar");
    }

    #[test]
    fn newest_sample_is_drawn_in_the_rightmost_column() {
        let visible = samples(&[Some(1_000), Some(8_000)]);
        let drawn = draw_one_row(&bars_newest_first(&visible, 1, 10_000), 5, 10_000);
        assert_eq!(
            drawn.chars().last(),
            Some('▆'),
            "newest bar not at the right edge: {drawn:?}"
        );
        assert_eq!(drawn.chars().take(3).collect::<String>(), "   ", "{drawn:?}");
        assert_eq!(
            drawn.chars().nth(3),
            Some('▁'),
            "older sample not left of newest: {drawn:?}"
        );
    }
}
