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

## Phase 2: mtr session, engine selection, throttle

### Design decisions
- `MtrSession` (`src/scan/traceroute/mtr.rs`) owns one family's `Accumulator` for the session's life and at most one child (`MtrRun`) at a time. One reader task per child reads stdout and stderr to EOF, then reaps the child and records its exit. Dropping the `MtrRun` aborts that task, which drops the `kill_on_drop` child, so the existing kill-on-drop path covers stall kills, protocol changes and quit.
- The task records the exit only after stdout is fully read. That way "exited before any parseable line" never misfires on output still buffered in the pipe when the process ends.
- `MtrSession::poll` returns `SessionPoll::{Streaming(TracerouteData), Failed(String), Unusable(String)}`. `Unusable` is the only thing that switches the engine; the scanner keeps the failure table out of its own code.
- The failure table is checked at `poll` time, once per 1s scan, not by a separate timer task. That covers both stall and startup grace, with the same resolution at the 1s cadence and no extra task to cancel.
- The startup wait (`MtrRun::wait_for_first_line`, up to `MTR_STARTUP_GRACE_SECS`) applies while the session has never parsed a line. That covers the first child and a network-failed family's retries. A respawn after good output does not block the scan; a silent respawned child is caught by the stall rule instead.
- Respawn throttle: when a child ends or is killed, `retry_at = now + MTR_RESPAWN_SECS` (`MtrSession::end_run`). That is at least `MTR_RESPAWN_SECS` after the last attempt too, so it meets both the Scheduling wording and the failure table's "respawn after 5s".
- Network-failure test (`mtr::network_failure`): `classify_route_error` on the joined stderr, where `NoRoute` or `Other("host unreachable")` counts as network. The family is `Failed(<classified text>)` and retries after the respawn delay; the failure clears once a later child parses a line.
- `EngineState::{Untried, Mtr { protocol, ipv4, ipv6 }, Traceroute { reason, last_run }}` sits behind a tokio `Mutex` on the scanner (`TracerouteScanner::engine`). A traced family with no address stores its no-address error instead of a session, and `family_outcome` turns it into `TracerouteStatus::NoAddress` as before.
- The traceroute throttle stores the last run's `TracerouteResult` (which is `Clone`), not the `Result<ScanResult>`. It rebuilds the outcome with `scan_outcome`, so a replayed failure keeps its type (`NoAddress` still downcasts).
- A traceroute run dropped by the scan deadline leaves `last_run.result = None`. Within the 5-minute window that replays as `timed out after 30s` (from `Scanner::deadline`), the same text `Scanner::run` records, instead of rerunning a 30s traceroute every second.
- The fallback reason reaches the data through `traceroute_protocol` -> `perform_traceroute_for_ip` -> `parse_traceroute_output(.., reason)`. `MTR_NOT_ATTEMPTED` is gone.
- The address lookup moved out of `traceroute_protocol` into `family_target_ip`, shared by both engines. Same checks and messages.
- `mtr_command` stdin is `/dev/null`. mtr has no reason to read it, and a child holding the terminal's stdin under the TUI would be a hazard.
- Live check on this Linux desktop (mtr 0.95): `timeout --foreground 8 target/debug/scan --no-tui 1.1.1.1` printed `IPv4 8 hops, reached`. While it ran, `ps` showed scan -> `mtr --raw -n -4 -m 30 -c 1000000 1.1.1.1` -> `mtr-packet` plus one more `mtr` with the same argv whose parent is the first mtr (mtr's own fork, not a second spawn). After scan exited, `pgrep -c -f '^mtr --raw -n -[46] -m 30'` printed `0` (AC3's command, run early on a debug build).

### Deviations
- The doc sets the startup grace, respawn and stall in seconds (`MTR_STARTUP_GRACE`, `MTR_RESPAWN_SECS`, `MTR_STALL_SECS`). They are constants grouped into `MtrTimings` (default = the doc's 5s/5s/10s), and a `#[cfg(test)]` `with_mtr_timings` shortens them so the fake-mtr tests run in milliseconds. Production values are unchanged and not configurable.
- The stall text is `mtr stalled: no output for 10s` built from the stall duration (`display_duration`), so test timings print `300ms`. Same text at the default.
- Gap filled: a spawn error other than `NotFound` (e.g. permission denied) falls back with `mtr: <io error>`. The table has no row for it; the Non-Goals say any non-network mtr failure falls back.
- Gap filled: the traceroute throttle replays the stored outcome only for the same protocol. A protocol change runs `traceroute` at once, as it did before this change. Replaying the old protocol's result would show the wrong family after `clear_for_protocol_change`.
- Test inverted by name: `test_traceroute_scanner_custom_config` asserted `interval() == 300s`. It now asserts `interval() == 1s` and `traceroute_interval == 300s`.
- `test_traceroute_scan_localhost` (live `traceroute` against 127.0.0.1) now pins the fallback with `with_mtr_program(MISSING_MTR)`. With mtr installed it would test mtr, whose first snapshot has no settled hop yet (the doc's `tracing route...` state). The existing `scan_with_fake` traceroute tests pin the fallback the same way.
- `TracerouteScanner` no longer derives `Clone`, because it now owns live sessions. Nothing cloned it.

### Tradeoffs
- Checking the failure table at poll time vs a watchdog task per child: the poll already runs every second, and a second task would need its own cancellation. The cost is that a stall is noticed up to one tick late.
- Tokio `Mutex` held across a whole fallback `traceroute` run (up to the 30s deadline) vs releasing it while running: one scan per scanner is in flight at a time anyway (`Scanner::run`), and holding the lock keeps the throttle free of races.
- One stdout+stderr reader task per child that reaps the child itself, vs the session calling `try_wait`: `try_wait` can see the exit before the last lines are read.

### Bite checks (2026-11-10; each break applied by a script in the session scratchpad, run with `cargo test --lib traceroute`, file restored and confirmed identical with `cmp`)
- `MTR_CYCLE_LIMIT` = 10: 3 failed (`args_are_raw_numeric_...`, `mtr_exit_after_output_...`, `protocol_change_...`).
- `MTR_OPTIONS` not removed: 1 failed (`command_strips_mtr_options_and_kills_on_drop`).
- Any stderr treated as a network failure: 3 failed (`network_failure_...`, `exit_without_output_...`, `silent_exit_...`).
- Network failures treated as non-network (sticky fallback): 2 failed (`network_failure_...`, `ipv6_route_error_fails_only_ipv6_and_ipv4_keeps_streaming`).
- Exit reason ignores stderr: 2 failed.
- Durations always shown in whole seconds: 2 failed (`durations_...`, `a_stalled_child_...`).
- No startup wait: 4 failed, incl. `no_line_within_the_grace_is_unusable`, `protocol_change_...`.
- Stall does not end the child: 1 failed (`a_stalled_child_fails_the_family_and_is_respawned`).
- `NotFound` not mapped: 2 failed (`missing_program_is_not_installed`, `missing_mtr_falls_back_and_throttles_traceroute`).
- No `forget_seqs` on respawn: 1 failed (`mtr_exit_after_output_...`: the old child's in-flight seq is settled as lost).
- Never respawn: 2 failed (stall, exit-after-output).
- `Accumulator::forget_seqs` clears nothing: 2 failed (`forget_seqs_keeps_counters_...`, `mtr_exit_after_output_...`).
- No traceroute throttle: 2 failed (`missing_mtr_...`, `fallback_traceroute_reruns_at_once_on_a_protocol_change`).
- Throttle ignores protocol: 1 failed (`fallback_traceroute_reruns_...`).
- No mtr restart on protocol change: 1 failed (`protocol_change_starts_a_fresh_mtr_session`).
- `interval()` back to 300s: 1 failed (`test_traceroute_scanner_custom_config`).
- `Unusable` family ignored instead of falling back: 5 failed, incl. every fallback traceroute test.
- Stdout reader drops lines: 5 failed, incl. `first_poll_waits_for_the_first_line_and_streams`.
- Restored: `cargo test --lib` 8 consecutive runs, 954 passed each; `otto ci` green, exit 0. A restore keeps the backup's older mtime, so the sources were `touch`ed before the final runs to force a rebuild.

### Open questions
- A family whose mtr fails with a network error before ever streaming retries every `MTR_RESPAWN_SECS`, and each retry's first scan waits for that child (it exits fast on ripr's IPv6 error, under 100ms). A network error that hangs instead of exiting would stall the scan up to the 5s grace on each retry and then fall back as `mtr: no output`. That matches the table, but it would turn a slow route failure into a sticky fallback. Flagging it, not changing it.
