# Implementation notes: mtr-style continuous traceroute

Design doc: `docs/plan/2026-11-10-mtr-traceroute.md`

## Phase 1: Raw parser, accumulator, extended types

### Design decisions
- `TracerouteHop::from_probes(hop_number, responses)` (`src/scan/traceroute.rs`) builds a hop from one traceroute line's probes and fills every aggregate field. `parse_hop_line` now ends in it, so the old inline stats moved there unchanged (best/avg/worst/packet_loss computed exactly as before).
- `from_probes` counts a non-timeout response as replied, even when its RTT failed to parse. That is what the old `is_silent` (`all(timeout)`) treated as an answer, so silence answers stay identical. An empty `responses` gives `replied == 0`, silent, as before.
- Test fixtures that set `best_rtt`/`avg_rtt`/`worst_rtt: None` or a hand-picked `packet_loss` keep those values through struct-update syntax over `from_probes` (`TracerouteHop { best_rtt: None, ..TracerouteHop::from_probes(..) }`), so the new fields stay consistent with `responses` while every value a rendering assertion reads is unchanged (`src/tui/traceroute.rs` `hop`/`tatari_route`, `src/tui/layout.rs` `traceroute_fixture`, `src/scan/traceroute.rs` `hop` and `destination_hop_tests::data`).
- `sample_stddev(count, sum_us, sum_sq_us)` (`src/scan/traceroute.rs`) is shared by the parser and the accumulator. It computes `n*sum_sq - sum^2` exactly in `u128` and goes to `f64` only for the divide and root, so a long session has no cancellation error. Rounded to whole microseconds.
- `destination_hop()` keeps its `destination_reached` guard and finds the last hop whose `current_address == target_ip` (`TracerouteData::destination_hop`). The guard is what `no_destination_hop_when_the_target_was_not_reached` pins.
- The accumulator keys hops by mtr's raw 0-based hop in a `BTreeMap` and adds 1 only at snapshot (`accumulator.rs:Accumulator::snapshot`).
- `parse_line` rejects raw hop 255, since hop 256 does not fit the `u8` hop numbers the rest of scan uses (`raw.rs:parse_line`). mtr runs with `-m 30`, so this never fires in practice.
- `Accumulator::apply_line` owns the "unparseable line: WARN and skip" rule and returns whether the line parsed, which Phase 2's startup-grace check ("first parseable line") can use directly.
- Fixtures came from fresh captures on this Linux desktop, mtr 0.95, 2026-11-10, not from ripr: `mtr --raw -n -c 2 1.1.1.1` (complete, 47 lines; it matches the doc's excerpt line for line apart from RTT values) and `mtr --raw -n -u -c 10 104.16.132.229`. The ECMP constant keeps only the raw-hop-6 lines of the latter, in stream order; hops are folded independently, so the omitted lines cannot change hop 7's counters. That capture showed 8 distinct `108.162.243.*` addresses over 10 probes, matching the Phase 0 count.
- Logging: per-record `apply` and per-second `snapshot` log at TRACE (hot paths); an ignored reply logs at DEBUG and an unparseable line at WARN, per the Accumulator rules.

### Deviations
- `Accumulator::snapshot` takes a fourth argument, `scan_duration: Duration`, beyond the doc's `snapshot(target_ip, ipv6, max_hops)`. `TracerouteData` requires the field and the pure accumulator has no clock; Phase 2's session knows how long it has run and passes it. Same effect, correct seam.
- The traceroute parser sets `engine = Traceroute { reason: "mtr not attempted" }` (`MTR_NOT_ATTEMPTED`). Nothing selects an engine until Phase 2, which replaces this constant with the real fallback reason. Not rendered anywhere until Phase 3.
- No test was inverted: helpers moved onto aggregate fields with the same answers, so every existing assertion stays as it was.

### Tradeoffs
- `pending` is a `Vec<u32>` vs a `HashSet`: it holds at most one seq in steady state, and membership is a linear scan of one element.
- Struct-update fixtures vs rewriting every fixture to computed stats: keeps existing pane/`--no-tui` assertions byte-identical in Phase 1; Phase 3 replaces these fixtures with mtr-mode data anyway.
- ECMP fixture filtered to hop 6 vs the full 307-line capture: the success criterion is about hop 7 only, and the full capture would bury it.

### Bite checks (2026-11-10; each break applied with `sed`, run with `cargo test --lib traceroute`, file restored and confirmed byte-identical with `cmp`)
- `raw.rs` hop guard `< u8::MAX` -> `<=`: 1 failed (`rejects_hop_255_and_accepts_hop_254`).
- `raw.rs` reply RTT parsed from the seq field: 4 failed, incl. `parses_each_record_type`, `late_reply_moves_a_lost_probe_back_to_replied`.
- `raw.rs` `split(' ')` instead of `split_whitespace`: 1 failed (`tolerates_surrounding_whitespace_and_a_trailing_newline`).
- Settling does not count lost: 4 failed, incl. `silent_hop_six_is_one_probe_sent_and_fully_lost`, `destination_is_hop_eight_...`.
- No retraction from the recent-lost list: 2 failed (`late_reply_...`, `a_reply_older_than_the_retract_window_stays_lost`).
- Retract window one larger: 1 failed (`a_reply_older_than_the_retract_window_stays_lost`).
- Pending seq not removed on reply: 3 failed, incl. `unknown_and_duplicate_replies_are_ignored`.
- `h` not de-duplicated: 2 failed (`ecmp_hop_lists_every_address_in_first_seen_order`, `answering_hops_carry_mtr_columns`).
- `current_address` from the first address instead of the latest `h`: 2 failed (ECMP, `a_path_that_gets_shorter_...`).
- Cycles counted on every hop: 1 failed (`engine_is_mtr_with_rounds_started`).
- `apply_line` reports an unparseable line as parsed: 1 failed (`unparseable_lines_are_skipped_and_reported`).
- No trimming above the destination: 2 failed (`destination_is_hop_eight_...`, `a_path_that_gets_shorter_...`).
- Snt-0 hops kept: 2 failed (`hops_with_no_settled_probe_are_left_out`, `stddev_is_the_sample_deviation_...`).
- Snapshot drops `ipv6`: 1 failed (`snapshot_carries_family_limits_and_duration`).
- `from_probes` replied = all probes: 8 failed, incl. `tui_and_no_tui_report_the_same_silent_hop_count`.
- `from_probes` current address = first answer: 1 failed (`parsed_hop_fills_the_aggregate_fields_from_its_probes`).
- `from_probes` addresses not de-duplicated: 1 failed (`repeated_address_is_listed_once_...`).
- Parser marks its output as `Mtr`: 1 failed (`parsed_output_is_marked_as_the_traceroute_engine`).
- `is_silent` back on `responses`: 2 failed (empty mtr `responses` read as silent).
- `destination_hop` back on `responses`: 2 failed (mtr hops have no responses).
- Population (n) stddev instead of sample (n-1): 4 failed, incl. `sample_stddev_matches_known_values`.
- Restored: `cargo test --lib scan::traceroute::accumulator` -> 13 passed; `otto ci` green, exit 0.

### Open questions
- `destination_hop()` now reads `current_address` (the last answering IP), per the Data Model. For a `traceroute` line where the target answered but a different router answered the hop's last probe, `destination_reached` is still true (the parser checks any response) while `destination_hop()` returns `None`. No existing test or capture shows that shape; flagging it rather than diverging from the doc.
