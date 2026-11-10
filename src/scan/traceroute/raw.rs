//! `mtr --raw` record grammar (mtr 0.95, observed): `x <hop> <seq>` probe sent,
//! `h <hop> <ip>` address seen at that hop, `p <hop> <rtt_us> <seq>` reply. `<hop>` is 0-based.

use std::net::IpAddr;

/// One parsed `mtr --raw` line. `hop` is mtr's 0-based hop index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawRecord {
    Sent { hop: u8, seq: u32 },
    Host { hop: u8, ip: IpAddr },
    Reply { hop: u8, rtt_us: u64, seq: u32 },
}

impl RawRecord {
    pub fn hop(&self) -> u8 {
        match self {
            RawRecord::Sent { hop, .. } | RawRecord::Host { hop, .. } | RawRecord::Reply { hop, .. } => *hop,
        }
    }
}

/// Parse one `mtr --raw` line; `None` for anything outside the grammar above.
///
/// Hop 255 is rejected: its 1-based number would not fit the `u8` hop numbers scan reports.
pub fn parse_line(line: &str) -> Option<RawRecord> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    let record = match fields.as_slice() {
        ["x", hop, seq] => RawRecord::Sent {
            hop: hop.parse().ok()?,
            seq: seq.parse().ok()?,
        },
        ["h", hop, ip] => RawRecord::Host {
            hop: hop.parse().ok()?,
            ip: ip.parse().ok()?,
        },
        ["p", hop, rtt_us, seq] => RawRecord::Reply {
            hop: hop.parse().ok()?,
            rtt_us: rtt_us.parse().ok()?,
            seq: seq.parse().ok()?,
        },
        _ => return None,
    };
    (record.hop() < u8::MAX).then_some(record)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_each_record_type() {
        assert_eq!(parse_line("x 5 33005"), Some(RawRecord::Sent { hop: 5, seq: 33005 }));
        assert_eq!(
            parse_line("h 0 10.10.10.1"),
            Some(RawRecord::Host {
                hop: 0,
                ip: "10.10.10.1".parse().unwrap()
            })
        );
        assert_eq!(
            parse_line("h 3 2606:4700:4700::1111"),
            Some(RawRecord::Host {
                hop: 3,
                ip: "2606:4700:4700::1111".parse().unwrap()
            })
        );
        assert_eq!(
            parse_line("p 7 5887 33007"),
            Some(RawRecord::Reply {
                hop: 7,
                rtt_us: 5887,
                seq: 33007
            })
        );
    }

    #[test]
    fn tolerates_surrounding_whitespace_and_a_trailing_newline() {
        assert_eq!(
            parse_line("  x 0 33000 \n"),
            Some(RawRecord::Sent { hop: 0, seq: 33000 })
        );
    }

    #[test]
    fn rejects_lines_outside_the_grammar() {
        for line in [
            "",
            "   ",
            "d 0 one.one.one.one",
            "x 0",
            "x 0 33000 extra",
            "h 0",
            "h 0 not-an-ip",
            "p 0 404",
            "p 0 404 33000 extra",
            "p 0 -1 33000",
            "p 0 4.04 33000",
            "x -1 33000",
            "x zero 33000",
            "x 256 33000",
            "X 0 33000",
            "mtr: udp socket connect failed: Cannot assign requested address",
        ] {
            assert_eq!(parse_line(line), None, "{line:?}");
        }
    }

    #[test]
    fn rejects_hop_255_and_accepts_hop_254() {
        assert_eq!(parse_line("x 255 33000"), None);
        assert_eq!(
            parse_line("x 254 33000"),
            Some(RawRecord::Sent { hop: 254, seq: 33000 })
        );
    }
}
