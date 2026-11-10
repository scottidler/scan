//! Folds an `mtr --raw` stream into mtr's per-hop columns (Loss%, Snt, Last, Avg, Best, Wrst,
//! StDev). Counters and sums only, so memory stays flat however long the stream runs.

use super::raw::{RawRecord, parse_line};
use super::{TraceEngine, TracerouteData, TracerouteHop, sample_stddev};
use std::collections::{BTreeMap, VecDeque};
use std::net::IpAddr;
use std::time::Duration;

/// How many settled-as-lost seqs per hop a late reply can still retract. Older losses are final.
pub const LOST_RETRACT_WINDOW: usize = 4;

#[derive(Debug, Default, Clone)]
struct HopCounters {
    replied: u32,
    lost: u32,
    last_rtt_us: Option<u64>,
    best_rtt_us: Option<u64>,
    worst_rtt_us: Option<u64>,
    sum_us: u128,
    sum_sq_us: u128,
    pending: Vec<u32>,
    recent_lost: VecDeque<u32>,
    latest_host: Option<IpAddr>,
    addresses: Vec<IpAddr>,
    current_address: Option<IpAddr>,
}

impl HopCounters {
    /// Settled probes: replied + lost. In-flight probes are not counted.
    fn sent(&self) -> u32 {
        self.replied + self.lost
    }

    fn probe_sent(&mut self, seq: u32) {
        for settled in std::mem::take(&mut self.pending) {
            self.lost += 1;
            self.recent_lost.push_back(settled);
            if self.recent_lost.len() > LOST_RETRACT_WINDOW {
                self.recent_lost.pop_front();
            }
        }
        self.pending.push(seq);
    }

    fn host_seen(&mut self, ip: IpAddr) {
        self.latest_host = Some(ip);
        if !self.addresses.contains(&ip) {
            self.addresses.push(ip);
        }
    }

    /// Counts the reply when `seq` is in flight or recently settled as lost; false otherwise.
    fn reply(&mut self, rtt_us: u64, seq: u32) -> bool {
        if let Some(index) = self.pending.iter().position(|&pending| pending == seq) {
            self.pending.swap_remove(index);
        } else if let Some(index) = self.recent_lost.iter().position(|&lost| lost == seq) {
            self.recent_lost.remove(index);
            self.lost -= 1;
        } else {
            return false;
        }
        self.replied += 1;
        self.last_rtt_us = Some(rtt_us);
        self.best_rtt_us = Some(self.best_rtt_us.map_or(rtt_us, |best| best.min(rtt_us)));
        self.worst_rtt_us = Some(self.worst_rtt_us.map_or(rtt_us, |worst| worst.max(rtt_us)));
        self.sum_us += u128::from(rtt_us);
        self.sum_sq_us += u128::from(rtt_us) * u128::from(rtt_us);
        self.current_address = self.latest_host;
        true
    }

    fn to_hop(&self, hop_number: u8) -> TracerouteHop {
        let sent = self.sent();
        let avg_rtt =
            (self.replied > 0).then(|| Duration::from_micros((self.sum_us / u128::from(self.replied)) as u64));
        TracerouteHop {
            hop_number,
            responses: Vec::new(),
            best_rtt: self.best_rtt_us.map(Duration::from_micros),
            avg_rtt,
            worst_rtt: self.worst_rtt_us.map(Duration::from_micros),
            packet_loss: if sent == 0 { 0.0 } else { self.lost as f32 / sent as f32 },
            sent,
            replied: self.replied,
            last_rtt: self.last_rtt_us.map(Duration::from_micros),
            stddev_rtt: sample_stddev(self.replied, self.sum_us, self.sum_sq_us),
            addresses: self.addresses.clone(),
            current_address: self.current_address,
        }
    }
}

/// Per-hop mtr counters for one stream, keyed by mtr's 0-based hop.
#[derive(Debug, Default, Clone)]
pub struct Accumulator {
    hops: BTreeMap<u8, HopCounters>,
    cycles: u32,
}

impl Accumulator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Probe rounds started: the count of `x` records for hop 0.
    pub fn cycles(&self) -> u32 {
        self.cycles
    }

    pub fn apply(&mut self, record: RawRecord) {
        log::trace!("[scan::traceroute::accumulator] apply: record={record:?}");
        match record {
            RawRecord::Sent { hop, seq } => {
                if hop == 0 {
                    self.cycles += 1;
                }
                self.hops.entry(hop).or_default().probe_sent(seq);
            }
            RawRecord::Host { hop, ip } => self.hops.entry(hop).or_default().host_seen(ip),
            RawRecord::Reply { hop, rtt_us, seq } => {
                let counted = self
                    .hops
                    .get_mut(&hop)
                    .is_some_and(|counters| counters.reply(rtt_us, seq));
                if !counted {
                    log::debug!(
                        "[scan::traceroute::accumulator] reply_ignored: hop={hop} seq={seq} rtt_us={rtt_us} (stale or unknown seq)"
                    );
                }
            }
        }
    }

    /// Parse and apply one raw line. An unparseable line is logged and skipped; returns whether
    /// the line parsed.
    pub fn apply_line(&mut self, line: &str) -> bool {
        match parse_line(line) {
            Some(record) => {
                self.apply(record);
                true
            }
            None => {
                log::warn!("[scan::traceroute::accumulator] unparseable_line: line={line:?}");
                false
            }
        }
    }

    /// The accumulated route. Hops above the lowest hop whose latest reply came from `target_ip`
    /// are dropped (mtr's first cycle probes one hop past the destination), and so are hops with
    /// no settled probe yet.
    pub fn snapshot(&self, target_ip: IpAddr, ipv6: bool, max_hops: u8, scan_duration: Duration) -> TracerouteData {
        let destination = self
            .hops
            .iter()
            .find(|(_, counters)| counters.current_address == Some(target_ip))
            .map(|(&raw_hop, _)| raw_hop);
        let hops: Vec<TracerouteHop> = self
            .hops
            .iter()
            .filter(|&(&raw_hop, counters)| destination.is_none_or(|dest| raw_hop <= dest) && counters.sent() > 0)
            .map(|(&raw_hop, counters)| counters.to_hop(raw_hop + 1))
            .collect();
        let total_hops = hops.last().map_or(0, |hop| hop.hop_number);
        log::trace!(
            "[scan::traceroute::accumulator] snapshot: target={target_ip} hops={} destination={destination:?} cycles={}",
            hops.len(),
            self.cycles
        );
        TracerouteData {
            hops,
            destination_reached: destination.is_some(),
            total_hops,
            max_hops,
            target_ip,
            scan_duration,
            ipv6,
            engine: TraceEngine::Mtr { cycles: self.cycles },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `mtr --raw -n -c 2 1.1.1.1`, mtr 0.95, captured 2026-11-10 on a Linux desktop. Raw hop 5
    /// never answers; cycle 1 probes raw hop 8, one past the destination at raw hop 7.
    const ONE_ONE_ONE_ONE_C2: &str = "\
x 0 33000
h 0 10.10.10.1
h 0 10.10.10.1
p 0 339 33000
x 1 33001
h 1 207.225.84.49
h 1 207.225.84.49
p 1 3024 33001
x 2 33002
h 2 207.225.86.129
h 2 207.225.86.129
p 2 9480 33002
x 3 33003
h 3 4.68.38.153
h 3 4.68.38.153
p 3 7029 33003
x 4 33004
h 4 4.69.219.206
h 4 4.69.219.206
p 4 6158 33004
x 5 33005
x 6 33006
h 6 108.162.243.11
h 6 108.162.243.11
p 6 6482 33006
x 7 33007
h 7 1.1.1.1
h 7 1.1.1.1
p 7 6069 33007
x 8 33008
h 8 1.1.1.1
h 8 1.1.1.1
p 8 6141 33008
x 0 33009
p 0 321 33009
x 1 33010
p 1 3120 33010
x 2 33011
p 2 3312 33011
x 3 33012
p 3 3471 33012
x 4 33013
p 4 6098 33013
x 5 33014
x 6 33015
p 6 6317 33015
x 7 33016
p 7 6919 33016
";

    /// Every raw-hop-6 line of `mtr --raw -n -u -c 10 104.16.132.229`, mtr 0.95, captured
    /// 2026-11-10 on a Linux desktop, in stream order. Hops are counted independently, so the
    /// other hops' lines are left out. 8 distinct addresses over 10 probes; `.62` and `.41`
    /// come back, so their `h` prints once.
    const ECMP_HOP6_U_C10: &str = "\
x 6 33006
h 6 108.162.243.62
h 6 108.162.243.62
p 6 10181 33006
x 6 33026
h 6 108.162.243.41
h 6 108.162.243.41
p 6 11923 33026
x 6 33046
h 6 108.162.243.11
h 6 108.162.243.11
p 6 8280 33046
x 6 33067
h 6 108.162.243.62
p 6 9098 33067
x 6 33088
h 6 108.162.243.59
h 6 108.162.243.59
p 6 16622 33088
x 6 33109
h 6 108.162.243.35
h 6 108.162.243.35
p 6 7173 33109
x 6 33130
h 6 108.162.243.33
h 6 108.162.243.33
p 6 5581 33130
x 6 33151
h 6 108.162.243.49
h 6 108.162.243.49
p 6 5993 33151
x 6 33172
h 6 108.162.243.45
h 6 108.162.243.45
p 6 6520 33172
x 6 33193
h 6 108.162.243.41
p 6 7638 33193
";

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("ip")
    }

    fn fold(stream: &str) -> Accumulator {
        let mut acc = Accumulator::new();
        for line in stream.lines() {
            assert!(acc.apply_line(line), "fixture line should parse: {line:?}");
        }
        acc
    }

    fn snap(acc: &Accumulator, target: &str) -> TracerouteData {
        acc.snapshot(ip(target), false, 30, Duration::from_secs(2))
    }

    fn hop(data: &TracerouteData, number: u8) -> &TracerouteHop {
        data.hops
            .iter()
            .find(|hop| hop.hop_number == number)
            .unwrap_or_else(|| panic!("hop {number} missing: {data:?}"))
    }

    #[test]
    fn silent_hop_six_is_one_probe_sent_and_fully_lost() {
        let data = snap(&fold(ONE_ONE_ONE_ONE_C2), "1.1.1.1");
        let silent = hop(&data, 6);
        assert_eq!(
            silent.sent, 1,
            "cycle 2's x 5 settles cycle 1's probe; cycle 2's is in flight"
        );
        assert_eq!(silent.replied, 0);
        assert_eq!(silent.packet_loss, 1.0);
        assert!(silent.is_silent());
        assert_eq!(silent.current_address, None);
        assert!(silent.addresses.is_empty());
    }

    #[test]
    fn destination_is_hop_eight_and_the_past_destination_probe_is_dropped() {
        let data = snap(&fold(ONE_ONE_ONE_ONE_C2), "1.1.1.1");
        assert!(data.destination_reached);
        assert_eq!(data.destination_hop().map(|hop| hop.hop_number), Some(8));
        assert!(data.hops.iter().all(|hop| hop.hop_number != 9), "{data:?}");
        assert_eq!(data.total_hops, 8);
        assert_eq!(
            data.hops.iter().map(|hop| hop.hop_number).collect::<Vec<_>>(),
            [1, 2, 3, 4, 5, 6, 7, 8]
        );
        assert_eq!(data.silent_hops(), 1);
        assert_eq!(data.last_reply_hop(), Some(8));
        assert_eq!(data.reach_label(), "reached");
    }

    #[test]
    fn answering_hops_carry_mtr_columns() {
        let data = snap(&fold(ONE_ONE_ONE_ONE_C2), "1.1.1.1");
        let gateway = hop(&data, 1);
        assert_eq!((gateway.sent, gateway.replied), (2, 2));
        assert_eq!(gateway.packet_loss, 0.0);
        assert_eq!(gateway.last_rtt, Some(Duration::from_micros(321)));
        assert_eq!(gateway.best_rtt, Some(Duration::from_micros(321)));
        assert_eq!(gateway.worst_rtt, Some(Duration::from_micros(339)));
        assert_eq!(gateway.avg_rtt, Some(Duration::from_micros(330)));
        // sample stddev of {339, 321}: |339 - 321| / sqrt(2) = 12.73
        assert_eq!(gateway.stddev_rtt, Some(Duration::from_micros(13)));
        assert_eq!(gateway.current_address, Some(ip("10.10.10.1")));
        assert_eq!(
            gateway.addresses,
            [ip("10.10.10.1")],
            "duplicate h lines are idempotent"
        );
        assert!(gateway.responses.is_empty());
    }

    #[test]
    fn engine_is_mtr_with_rounds_started() {
        let acc = fold(ONE_ONE_ONE_ONE_C2);
        assert_eq!(acc.cycles(), 2);
        assert!(matches!(snap(&acc, "1.1.1.1").engine, TraceEngine::Mtr { cycles: 2 }));
    }

    #[test]
    fn ecmp_hop_lists_every_address_in_first_seen_order() {
        let data = snap(&fold(ECMP_HOP6_U_C10), "104.16.132.229");
        let ecmp = hop(&data, 7);
        assert_eq!(
            ecmp.addresses,
            [
                ip("108.162.243.62"),
                ip("108.162.243.41"),
                ip("108.162.243.11"),
                ip("108.162.243.59"),
                ip("108.162.243.35"),
                ip("108.162.243.33"),
                ip("108.162.243.49"),
                ip("108.162.243.45"),
            ]
        );
        assert_eq!(ecmp.sent, 10);
        assert_eq!(ecmp.packet_loss, 0.0);
        assert_eq!(ecmp.current_address, Some(ip("108.162.243.41")), "the latest reply's h");
        assert!(!data.destination_reached);
    }

    #[test]
    fn late_reply_moves_a_lost_probe_back_to_replied() {
        let mut acc = Accumulator::new();
        for line in ["x 0 33000", "h 0 192.0.2.1", "x 0 33009"] {
            acc.apply_line(line);
        }
        let before = snap(&acc, "192.0.2.1");
        assert_eq!(before.hops[0].sent, 1);
        assert_eq!(before.hops[0].packet_loss, 1.0);

        acc.apply_line("p 0 1500000 33000");
        let after = snap(&acc, "192.0.2.1");
        assert_eq!(after.hops[0].sent, 1);
        assert_eq!(after.hops[0].replied, 1);
        assert_eq!(after.hops[0].packet_loss, 0.0);
        assert_eq!(after.hops[0].last_rtt, Some(Duration::from_millis(1500)));
        assert!(after.destination_reached);
    }

    #[test]
    fn a_reply_older_than_the_retract_window_stays_lost() {
        let mut acc = Accumulator::new();
        for seq in 0..=LOST_RETRACT_WINDOW as u32 + 1 {
            acc.apply(RawRecord::Sent { hop: 0, seq });
        }
        acc.apply(RawRecord::Reply {
            hop: 0,
            rtt_us: 900,
            seq: 0,
        });
        let data = snap(&acc, "192.0.2.1");
        assert_eq!(data.hops[0].sent, LOST_RETRACT_WINDOW as u32 + 1);
        assert_eq!(
            data.hops[0].replied, 0,
            "seq 0 fell out of the window, its loss is final"
        );

        acc.apply(RawRecord::Reply {
            hop: 0,
            rtt_us: 900,
            seq: 1,
        });
        assert_eq!(snap(&acc, "192.0.2.1").hops[0].replied, 1, "seq 1 is still retractable");
    }

    #[test]
    fn unknown_and_duplicate_replies_are_ignored() {
        let mut acc = Accumulator::new();
        acc.apply_line("p 3 500 33000");
        acc.apply_line("x 0 33000");
        acc.apply_line("p 0 500 33000");
        acc.apply_line("p 0 500 33000");
        acc.apply_line("p 0 500 40000");
        let data = snap(&acc, "192.0.2.1");
        assert_eq!(data.hops.len(), 1, "{data:?}");
        assert_eq!((data.hops[0].sent, data.hops[0].replied), (1, 1));
    }

    #[test]
    fn hops_with_no_settled_probe_are_left_out() {
        let mut acc = Accumulator::new();
        acc.apply_line("x 0 33000");
        acc.apply_line("x 1 33001");
        acc.apply_line("p 0 400 33000");
        let data = snap(&acc, "192.0.2.1");
        assert_eq!(data.hops.iter().map(|hop| hop.hop_number).collect::<Vec<_>>(), [1]);
        assert_eq!(data.total_hops, 1);
        assert!(!data.destination_reached);
        assert_eq!(data.reach_label(), "target silent (last reply: hop 1)");
    }

    #[test]
    fn a_path_that_gets_shorter_drops_the_hops_above_the_new_destination() {
        let mut acc = Accumulator::new();
        for line in [
            "x 0 1",
            "h 0 10.0.0.1",
            "p 0 100 1",
            "x 1 2",
            "h 1 192.0.2.1",
            "p 1 200 2",
        ] {
            acc.apply_line(line);
        }
        assert_eq!(snap(&acc, "192.0.2.1").total_hops, 2);
        for line in ["x 0 3", "h 0 192.0.2.1", "p 0 100 3"] {
            acc.apply_line(line);
        }
        let data = snap(&acc, "192.0.2.1");
        assert_eq!(data.total_hops, 1);
        assert_eq!(data.destination_hop().map(|hop| hop.hop_number), Some(1));
        assert_eq!(data.hops[0].addresses, [ip("10.0.0.1"), ip("192.0.2.1")]);
    }

    #[test]
    fn stddev_is_the_sample_deviation_and_needs_two_replies() {
        let mut acc = Accumulator::new();
        for (seq, rtt_us) in [(1, 10_000), (2, 20_000), (3, 30_000)] {
            acc.apply(RawRecord::Sent { hop: 0, seq });
            if seq == 1 {
                assert_eq!(snap(&acc, "192.0.2.1").hops.len(), 0);
            }
            acc.apply(RawRecord::Reply { hop: 0, rtt_us, seq });
            if seq == 1 {
                assert_eq!(snap(&acc, "192.0.2.1").hops[0].stddev_rtt, None);
            }
        }
        let hop = snap(&acc, "192.0.2.1").hops[0].clone();
        assert_eq!(hop.stddev_rtt, Some(Duration::from_millis(10)));
        assert_eq!(hop.avg_rtt, Some(Duration::from_millis(20)));
    }

    #[test]
    fn unparseable_lines_are_skipped_and_reported() {
        let mut acc = Accumulator::new();
        assert!(!acc.apply_line("mtr: udp socket connect failed: Cannot assign requested address"));
        assert!(!acc.apply_line("x 0"));
        assert!(acc.apply_line("x 0 33000"));
        assert_eq!(acc.cycles(), 1);
    }

    #[test]
    fn snapshot_carries_family_limits_and_duration() {
        let acc = Accumulator::new();
        let target = ip("2606:4700:4700::1111");
        let data = acc.snapshot(target, true, 30, Duration::from_secs(7));
        assert!(data.hops.is_empty());
        assert!(data.ipv6);
        assert_eq!(data.max_hops, 30);
        assert_eq!(data.target_ip, target);
        assert_eq!(data.scan_duration, Duration::from_secs(7));
        assert!(matches!(data.engine, TraceEngine::Mtr { cycles: 0 }));
    }
}
