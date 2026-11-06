//! Ping latency history for the connectivity graphs, and the pure math that turns a visible
//! window of it into braille dots: the stepped scale, the one-dot floor, and newest at the right.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Scale ceilings in ms. 5000 is the ping timeout (`scan/ping.rs`), so no reply exceeds it.
const SCALE_STEPS_MS: [u64; 12] = [1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000];
const MICROS_PER_MS: u64 = 1000;
/// A braille cell is 2 dots wide and 4 dots tall, so each cell column holds two samples.
pub const SAMPLES_PER_CELL: usize = 2;
const DOTS_PER_ROW: u64 = 4;
const BRAILLE_BASE: u32 = 0x2800;
/// Dot bits per column, bottom dot first: left column dots 7,3,2,1; right column dots 8,6,5,4.
const DOT_BITS: [[u8; 4]; 2] = [[0x40, 0x04, 0x02, 0x01], [0x80, 0x20, 0x10, 0x08]];

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

    /// Every kept sample, oldest first.
    pub fn all(&self) -> Vec<Sample> {
        self.samples.iter().copied().collect()
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

/// Percent of `samples` that got no reply, rounded; `None` with no samples.
pub fn loss_percent(samples: &[Sample]) -> Option<u64> {
    if samples.is_empty() {
        return None;
    }
    let lost = samples.iter().filter(|(_, micros)| micros.is_none()).count() as u64;
    Some((lost * 100 + samples.len() as u64 / 2) / samples.len() as u64)
}

/// Mean absolute difference, in µs, between the round trips of consecutive cycles that both got a
/// reply; `None` when no two consecutive cycles did.
pub fn jitter_us(samples: &[Sample]) -> Option<u64> {
    let deltas: Vec<u64> = samples
        .windows(2)
        .filter_map(|pair| match (pair[0].1, pair[1].1) {
            (Some(a), Some(b)) => Some(a.abs_diff(b)),
            _ => None,
        })
        .collect();
    if deltas.is_empty() {
        return None;
    }
    Some(deltas.iter().sum::<u64>() / deltas.len() as u64)
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

/// How many dots tall a reply of `micros` is at scale `max_us` in a graph `total` dots tall. A
/// reply too small to draw is raised to one dot, and none is taller than the graph.
fn dot_height(micros: u64, max_us: u64, total: u64) -> u64 {
    if total == 0 || max_us == 0 {
        return 0;
    }
    (micros.saturating_mul(total).div_ceil(max_us)).clamp(1, total)
}

/// `samples` as a `rows` x `cols` braille grid against a 0..`max_us` scale, top row first. Each
/// sample is a bar of dots rising from the bottom, two samples per cell, the newest in the
/// rightmost dot column. A failed ping draws nothing: its slot on the time axis stays a gap.
pub fn braille_grid(samples: &[Sample], rows: u16, cols: u16, max_us: u64) -> Vec<Vec<char>> {
    let rows = usize::from(rows);
    let cols = usize::from(cols);
    let total = rows as u64 * DOTS_PER_ROW;
    let mut bits = vec![vec![0u8; cols]; rows];
    let dot_columns = cols * SAMPLES_PER_CELL;
    let shown = samples.len().min(dot_columns);
    let first = dot_columns - shown;
    for (index, (_, micros)) in samples[samples.len() - shown..].iter().enumerate() {
        let dot_column = first + index;
        let (col, side) = (dot_column / SAMPLES_PER_CELL, dot_column % SAMPLES_PER_CELL);
        let height = micros.map_or(0, |micros| dot_height(micros, max_us, total));
        for dot in 0..height {
            let row = rows - 1 - (dot / DOTS_PER_ROW) as usize;
            bits[row][col] |= DOT_BITS[side][(dot % DOTS_PER_ROW) as usize];
        }
    }
    bits.into_iter()
        .map(|row| {
            row.into_iter()
                .map(|cell| char::from_u32(BRAILLE_BASE + u32::from(cell)).unwrap_or(' '))
                .collect()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn samples(values: &[Option<u64>]) -> Vec<Sample> {
        let start = Instant::now();
        values
            .iter()
            .enumerate()
            .map(|(i, micros)| (start + Duration::from_secs(i as u64), *micros))
            .collect()
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

    fn glyphs(grid: &[Vec<char>]) -> Vec<String> {
        grid.iter().map(|row| row.iter().collect()).collect()
    }

    #[test]
    fn a_full_scale_reply_fills_its_dot_column_to_the_top() {
        // One cell, two rows: 8 dots tall. The newest sample is the right dot column.
        let grid = braille_grid(&samples(&[Some(10_000)]), 2, 1, 10_000);
        assert_eq!(glyphs(&grid), vec!["⢸", "⢸"]);
    }

    #[test]
    fn two_samples_share_a_cell_oldest_on_the_left() {
        // 2.5ms of 10ms in 4 dots is 1 dot; 10ms is 4 dots.
        let grid = braille_grid(&samples(&[Some(2_500), Some(10_000)]), 1, 1, 10_000);
        assert_eq!(glyphs(&grid), vec!["⣸"]);
    }

    #[test]
    fn a_reply_too_small_to_draw_is_raised_to_one_dot() {
        let grid = braille_grid(&samples(&[Some(1)]), 2, 1, 1_000);
        assert_eq!(glyphs(&grid), vec!["\u{2800}", "⢀"]);
    }

    #[test]
    fn half_millisecond_reply_at_one_millisecond_scale_is_half_the_height() {
        let grid = braille_grid(&samples(&[Some(500)]), 1, 1, 1_000);
        assert_eq!(glyphs(&grid), vec!["⢠"]);
    }

    #[test]
    fn newest_samples_sit_at_the_right_edge_and_older_ones_drop_off_the_left() {
        let values: Vec<Option<u64>> = (1..=7).map(|ms| Some(ms * 1_000)).collect();
        let grid = braille_grid(&samples(&values), 1, 3, 4_000);
        // 6 dot columns show samples 2..=7; 4ms+ fill all 4 dots.
        assert_eq!(glyphs(&grid), vec!["⣴⣿⣿"]);
    }

    #[test]
    fn a_failed_ping_leaves_its_dot_column_empty() {
        let grid = braille_grid(&samples(&[Some(1_000), None, Some(1_000), Some(1_000)]), 1, 2, 4_000);
        assert_eq!(glyphs(&grid), vec!["⡀⣀"]);
        let all_failed = braille_grid(&samples(&[None, None, None, None]), 2, 2, 4_000);
        assert_eq!(glyphs(&all_failed), vec!["\u{2800}\u{2800}", "\u{2800}\u{2800}"]);
    }

    #[test]
    fn fewer_samples_than_columns_leave_the_left_blank() {
        let grid = braille_grid(&samples(&[Some(4_000)]), 1, 3, 4_000);
        assert_eq!(glyphs(&grid), vec!["\u{2800}\u{2800}⢸"]);
    }

    #[test]
    fn loss_percent_counts_failed_cycles() {
        assert_eq!(loss_percent(&[]), None);
        assert_eq!(loss_percent(&samples(&[Some(1), None, Some(1), Some(1)])), Some(25));
        assert_eq!(loss_percent(&samples(&[None, None])), Some(100));
        assert_eq!(loss_percent(&samples(&[Some(1), None, None])), Some(67));
    }

    #[test]
    fn jitter_averages_consecutive_reply_differences_and_skips_failures() {
        assert_eq!(jitter_us(&samples(&[Some(1000)])), None);
        assert_eq!(jitter_us(&samples(&[Some(1000), None, Some(5000)])), None);
        // 1000 -> 3000 -> 2000: differences 2000 and 1000.
        assert_eq!(jitter_us(&samples(&[Some(1000), Some(3000), Some(2000)])), Some(1500));
        assert_eq!(
            jitter_us(&samples(&[Some(1000), Some(3000), None, Some(9000)])),
            Some(2000)
        );
    }

    #[test]
    fn all_returns_every_kept_sample_oldest_first() {
        let mut data = SparklineData::new(3);
        let start = Instant::now();
        for ms in 1..=4u64 {
            data.add_sample(start + Duration::from_secs(ms), Some(Duration::from_millis(ms)));
        }
        let micros: Vec<Option<u64>> = data.all().iter().map(|(_, micros)| *micros).collect();
        assert_eq!(micros, vec![Some(2000), Some(3000), Some(4000)]);
    }
}
