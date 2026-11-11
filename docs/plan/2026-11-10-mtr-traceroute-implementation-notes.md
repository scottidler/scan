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

## Phase 3: TUI pane and `--no-tui` line

### Design decisions
- `TracerouteHop::loss_percent` (`src/scan/traceroute.rs`) is the one Loss% both renderers read: lost / settled, rounded to a whole percent, `None` before any probe settled. The pane and `pretty.rs` cannot disagree, and the traceroute fallback's hops get it free (`sent = 3`).
- Rendering branches on `TracerouteData.engine`, not on whether `responses` is empty (`src/tui/traceroute.rs:is_mtr`). Fallback data keeps the old per-probe grid and zoom byte for byte; mtr data gets the new rows and table.
- Normal grid row under mtr: `mtr_hop_row` writes `<hop>: <current_address> +N <loss> <avg>`, single-space separated so a hop fits the 80x24 dashboard pane (25 inner columns). The destination hop keeps its own `->` row, now `(avg loss)`.
- Zoom (`mtr_table_lines`): `Hop Host Loss% Snt Last Avg Best Wrst StDev`, host column sized to the longest address, one-decimal ms so sub-millisecond hops do not read `0ms`, and an indented row for each address other than `current_address`. A hop with no reply shows `???` and `-` cells.
- Before the first settled probe (mtr engine, no hops) the pane and the `--no-tui` line both read `tracing route...` instead of `target silent`.
- The status header names the engine once the scan is Complete: `Status: mtr · 42 cycles` (GOOD) or `Status: traceroute (mtr not installed)` (WARN). Running, refreshing and failed labels still win, so a failure is never hidden behind the engine name.
- `--no-tui`: `IPv4 8 hops, reached (6ms, loss 0%, 1 no reply, mtr 42 cycles)`; fallback `... (5ms, loss 0%, 4 no reply, 3003ms, traceroute: mtr not installed)`. Loss and RTT come from the destination hop (last hop when not reached).
- Fixtures: `traceroute_fixture` (`src/tui/layout.rs`) and `tatari_route` (`src/tui/traceroute.rs`) now carry mtr-mode data (empty `responses`, aggregates filled). The old probe-level `tatari_route` is `tatari_fallback_route`, used by the tests that read `responses` (destination RTT, zoomed probes, 80x24 fallback fit, variation selector); `ipv6_route` and `route_with_silent_hops` stay fallback.

### Deviations
- No Loss% threshold exists in the connectivity pane: it colors by connection state and latency (`SLOW_LATENCY_US`, `VERY_SLOW_LATENCY_US`), never by loss percent. The doc says to reuse its thresholds, so I added `BAD_LOSS_PERCENT = 10` (`src/tui/traceroute.rs`): 0% GOOD, below 10% WARN, 10% and above BAD. Colors are the shared theme constants.
- The engine is the Status header text, not a separate line: the doc's `Status: mtr · 42 cycles`. A separate engine row pushed the fallback pane's Duration row off the 80x24 dashboard ("1 more"), so the header carries it. At that width the narrow pane clips it (`mtr · 42 cycl...`); zoom shows it in full.
- The `Duration:` row is omitted under mtr: a snapshot of live counters is instant, so the figure (0ms) would be a lie, and `--no-tui` drops the duration for the same reason. The fallback keeps both. The 80x24 fit test was split: an mtr test (no Duration) and a fallback test (Duration last row).
- Destination row under mtr reads `(3ms 0%)` rather than `(3ms, loss 0%)`, to stay inside the 25-column dashboard pane.
- Test renamed/split by name: `tatari_route_fits_the_80x24_dashboard_with_destination_and_duration` became `tatari_route_fits_the_80x24_dashboard_with_engine_and_destination` (mtr) plus `fallback_route_fits_the_80x24_dashboard_with_destination_and_duration`.

### Tradeoffs
- Branch on engine vs one renderer for both: the fallback's per-probe detail (every probe's address and RTT) has no mtr equivalent, and dropping it would change shipped fallback output for no gain.
- Fixed 10% BAD threshold vs inventing a config key: the doc excludes new config; a constant is the smallest honest choice.

### Bite checks (2026-11-10; each break applied by a script in the session scratchpad, run with `cargo test --lib`, file restored after)
- `loss_percent` without rounding: 1 failed (`loss_percent_rounds_settled_probes_and_is_none_before_any`).
- `StDev` header renamed: 1 failed (`zoomed_mtr_table_has_every_column_and_ecmp_rows`).
- `BAD_LOSS_PERCENT` 10 -> 30: 1 failed (`mtr_loss_is_colored_good_warn_bad_by_threshold`); 0% colored WARN: same test.
- `tracing route...` branch disabled: 1 failed (`mtr_pane_says_tracing_route_before_any_hop_settles`).
- `+N` count forced to 0: 1 failed (`mtr_grid_row_shows_address_extras_loss_and_average`).
- ECMP extra rows dropped: 1 failed (`zoomed_mtr_table_has_every_column_and_ecmp_rows`).
- Duration always shown: 2 failed (the mtr fit test and the zoom test).
- Cycle count not shown: 3 failed (incl. the mtr fit test).
- mtr destination note disabled: 1 failed (the mtr fit test).
- `--no-tui` cycles off by one: 1 failed (`traceroute_line_carries_mtr_cycles_and_destination_loss`); loss off by one: 2 failed; loss from the first hop: 1 failed (`traceroute_line_shows_the_destination_hops_loss_not_a_transit_hops`); `tracing route...` removed: 1 failed.
- Fallback reason text dropped from the pane header: 1 failed (`zoomed_fallback_names_the_engine_reason`); from the `--no-tui` line: 1 failed (`traceroute_line_names_why_the_fallback_is_in_use`); Duration hidden for the fallback: 3 failed.

### Open questions
- Is the 10% BAD loss threshold right? It is a judgment call; the connectivity pane gave nothing to reuse.
- The shakedown the doc lists (release build on ripr, TUI over tmux, a run past 15s, macOS) is not part of this phase and has not been run; AC1-AC3's long-run commands were not executed here beyond the single 8s debug run in the report.

## Audit fixes (round 1)

Findings from the round 1 implementation audit (M2, M3, C1, C2, C3, D1, D2, plus the doc's TUI bullet). M1 (the 1s replay re-stamping `last_updated`) is not in this round; it waits on an owner decision.

### Design decisions
- M2: `TracerouteData::is_destination(hop)` (`src/scan/traceroute.rs`) is the one rule, by engine. Traceroute: `hop.addresses.contains(&target_ip)`, the v0.6.4 "target answered any probe" rule for one run's 3 probes. mtr: `hop.current_address == Some(target_ip)`, because mtr's `addresses` are cumulative. `destination_hop()` and `parse_traceroute_output`'s `destination_reached` both call it, so they cannot disagree. This also settles the Phase 1 open question.
- M3: `MtrSession::poll` (`src/scan/traceroute/mtr.rs`) now checks `network_failure(stderr)` in the no-output branch before declaring mtr unusable. On a match it calls `end_run` (dropping the run kills the child), sets that family's `failure`, and retries after the respawn delay. The engine stays mtr. This settles the Phase 2 open question: the failure table's "Detected by" is the stderr content, whether the child exits or hangs.
- C1: `destination_line` (`src/tui/traceroute.rs`) under mtr builds the row like `mtr_hop_row`: `+N` in VALUE for the extra addresses, then `(avg loss)` with the loss span colored by `loss_color` (the same `BAD_LOSS_PERCENT` thresholds).
- C2: `FallbackFailure { failure, reason }` (`src/scan/traceroute.rs`) is the error when every fallback family fails. It displays as `IPv4: no IPv4 route on this host (traceroute: mtr not installed)`. `fallback_outcome` wraps both a fresh run and a throttled replay (including the replayed `timed out after 30s`). A `NoAddress` outcome passes through unwrapped, because no address is not a failure and `status_label` downcasts it. `--no-tui` prints the error's Display, so it names the reason with no renderer change; the pane reads `reason` back by downcast.
- C3: the fallback reason goes on the pane's bottom border, left-aligned as `─┘mtr not installed└`, when the Status header is too wide for the pane. New `Pane::border_note(state, width)` (default `None`) and `border_note_line` (`src/tui/pane.rs`) draw it in the room the overflow marker and key legend leave, clipped with `…`. The traceroute pane's `border_note` returns the reason (`fallback_reason`: from a `FallbackFailure` error first, else from the shown route's engine) only when `header_line(state)` is wider than the pane. Wide panes and zoom already show it in the header, so they get no duplicate. `header_line` was pulled out of `content` so both read one header.
- D1: when `poll_mtr` returns a fallback reason after the scan has already spent `startup_grace`, `scan()` switches the engine and returns `FallbackFailure { failure: "first run on the next scan", reason }` without running traceroute. The next 1s tick runs it with the whole scan deadline. An instant fallback (`mtr not installed`, a fast exit) still runs traceroute in the same scan, as before.
- D2: a respawn's spawn error already returned `Unusable`, so the scanner already fell back with the matching reason (`mtr not installed` for `NotFound`, `mtr: <io error>` otherwise). Two new tests pin it: the fake mtr streams, exits, and is then removed or made non-executable. The next result is traceroute's, with that reason. If the fallback traceroute then fails as well, the error names the reason (C2); see Open questions for the route the Scanner keeps.
- Doc: the TUI bullet names `BAD_LOSS_PERCENT = 10` and drops "reuse the connectivity thresholds". The Data Model "Helpers" bullet states the per-engine destination rule. The failure table's network and no-output rows, and the Grid bullet, now describe M3, D1, C1, C2 and C3.

### Deviations
- C3: the reason is on the bottom border, not on its own wrapped line. At 80x24 the fallback pane has 8 inner rows (27x10 cell) and the fit fixture fills all 8 (header, reach, destination, 4 hop rows, Duration). Any extra content row pushes Duration off and breaks `fallback_route_fits_the_80x24_dashboard_with_destination_and_duration`, the same problem Phase 3 hit. The border is the only room left. The note shows only when the header clips the reason.
- D1: the first fallback scan after the grace returns an `Err` (`first run on the next scan (traceroute: mtr: no output)`), so for that one tick the pane reads `failed: ...` and `--no-tui` prints it. The brief offered "return the fallback result"; there is no traceroute result yet, and an `Ok` with no data would read `All protocols failed` with no reason.
- Doc amended beyond the two named bullets: the failure table's network and no-output rows (M3, D1) and one Grid bullet (C1, C2, C3), so the doc describes the shipped behavior.

### Tradeoffs
- D1 defers on `spent >= startup_grace` vs on any time spent: an instant fallback loses a few milliseconds of the deadline, and deferring it would turn every first `mtr not installed` scan into a one-tick error. The cost: a child that exits with a non-network error just under the grace still runs traceroute in the same scan with up to `grace` less deadline (at most 5s of 30s).
- M3 checks stderr at the grace vs waking on each stderr line: a hung child with a network error still holds that family's poll for the grace on each retry (the Phase 2 behavior for a fast exit was under 100ms). Under `Both`, that poll runs concurrently with the other family's, so the healthy family keeps streaming. The scan just returns up to 5s later on those retry ticks. Waking early needs the stderr reader to notify and the waiter to classify. The fix the audit asked for is the check at the grace.
- C3 border note vs shortening the reason text: reasons include mtr's own stderr (`mtr: Failure to open sockets`), which no fixed abbreviation covers. The border clips with `…` like every other row.
- C2 typed error vs folding the reason into `TracerouteResult`: the error path has no `TracerouteData` to carry the engine. A typed error leaves the Scanner's Ok/Err semantics and history unchanged.

### Bite checks (2026-11-10; each break applied by a script in the session scratchpad, run with `cargo test --lib <filter>`, file restored from a backup and confirmed identical with `cmp`)
- M2 traceroute rule back to `current_address`: 2 failed (`traceroute_destination_is_the_hop_where_the_target_answered_any_probe`, `mtr_destination_follows_the_latest_reply_not_every_address_seen`).
- M2 mtr rule switched to `addresses.contains`: 1 failed (`mtr_destination_follows_the_latest_reply_not_every_address_seen`).
- M3 network check removed from the no-output branch: 2 failed (`a_hung_child_with_a_network_error_fails_the_family_and_is_retried`, `hung_ipv6_route_error_fails_only_ipv6_and_ipv4_keeps_streaming`).
- C2 error not wrapped: 1 failed (`every_fallback_family_failing_still_names_the_fallback_reason`). Display drops the reason: 2 failed (that test plus `every_fallback_family_failing_still_says_why_traceroute_is_in_use`).
- D1 never defers: 1 failed (`fallback_after_the_startup_grace_runs_traceroute_on_the_next_scan`).
- D2 respawn `NotFound` reported as a family failure: 1 failed (`mtr_removed_mid_run_falls_back_as_not_installed`). Other respawn spawn errors reported the same way: 1 failed (`mtr_unrunnable_mid_run_falls_back_with_the_spawn_error`).
- C1 `+N` suppressed: 1 failed (`mtr_destination_row_colors_its_loss_and_counts_extra_addresses`). Loss drawn MUTED: 2 failed (that test plus `mtr_destination_row_with_no_loss_reads_good_and_has_no_extras`).
- C3 note never shown: 3 failed (`fallback_reason_is_on_the_border_when_the_80x24_header_clips_it`, `a_long_fallback_reason_is_clipped_on_the_border`, `every_fallback_family_failing_still_says_why_traceroute_is_in_use`). Note always shown: 1 failed (the first). Note not clipped: 1 failed (`border_note_fits_whole_or_clipped_to_its_room`). No-room guard removed: 1 failed (`border_note_with_no_room_for_text_is_none`). Note shown under mtr: 1 failed (`mtr_pane_has_no_border_note_at_80x24`).
- Existing 80x24 fit tests (`tatari_route_fits_the_80x24_dashboard_with_engine_and_destination`, `fallback_route_fits_the_80x24_dashboard_with_destination_and_duration`) unchanged and green.

### Open questions
- D2 residue: when mtr vanishes mid-run and the fallback traceroute also fails, the Scanner keeps the last good result, as it does for every scanner. The pane body and the `--no-tui` line still show that mtr route, under an error that now names the fallback reason. Clearing it needs a Scanner seam (an outcome that drops the retained result). That is the same seam M1 is weighing, so it should be decided with M1.
- Under a fallback failure, the 80x24 header row clips the failure text itself (`failed: IPv4:…`). The border shows the reason, but the failure is visible only in a wider pane or zoom. Wrapping the header row when there is no route (the `wrapped` index in `to_rows`) would show it. That was not in this round's list.

## Audit fixes (round 2, owner decisions)

Owner decisions of 2026-11-10: M1 option A (a replay signal on `Scanner`), the D2 residue from round 1's open questions, and the 80x24 header that clipped the failure text.

### Design decisions
- M1: `ScanKind { Measured, MeasuredAfterReset, Replayed }` and a default method `Scanner::last_scan_kind() -> ScanKind` (`src/scanner.rs`), returning `Measured`, so every other scanner is unchanged. `Scanner::run` reads it after each scan: `Replayed` skips `record_outcome` and puts back the status `mark_running` replaced (`mark_running` now returns it; `restore_status`), so status, `last_updated` and history stay as the run that produced the outcome left them, and a stored failure logs at ERROR once.
- M1: `TracerouteScanner` keeps `last_scan_kind: std::sync::Mutex<ScanKind>` (`src/scan/traceroute.rs`). `scan()` sets `Measured` before its first await, so a scan dropped at its deadline never reports the previous scan's kind; `traceroute_engine`'s throttled branch sets `Replayed`.
- M1: a scan that hits its deadline is recorded as timed out even if the scanner last reported `Replayed` (`run` maps `(timed out, Replayed)` to `Measured`). A replay with no prior state to restore (impossible today) is recorded, so the pane can never stay on Running.
- D2: the same signal carries a third value. The scan that switches the engine from mtr to the fallback reports `MeasuredAfterReset`; `run` calls `clear_retained` (result, error, history; it shares `drop_retained` with `clear_for_protocol_change`) before recording. A failing fallback after mtr vanishes therefore shows only its error (which names the reason, round 1's C2), not the last mtr route; a succeeding one starts history over with no mtr snapshots in it. The deferred-first-run case (D1) is covered too, since it switches in the same place.
- Header: `header_wraps(state)` (`src/tui/traceroute.rs`) is true when no `ScanResult::Traceroute` is retained; `content` then passes index 0 in `to_rows`' `wrapped`, so the Status header wraps over the free rows. At 80x24 the all-fail header reads in four rows: `🧭 Status: failed: IPv4: / no IPv4 route on this / host (traceroute: mtr / not installed)`. With a route retained the header stays one row, so every 80x24 fit test is unchanged and green.
- Header: `border_note` returns `None` when the header wraps, since the wrapped header already shows the reason.
- Doc: Overview's "No `Scanner` trait change" now describes the additive default method; Architecture lists `src/scanner.rs`; Scheduling gains the replay and reset bullets; the TUI section gains the wrapped header; Resolved Decisions gains the M1 entry in the owner's words.

### Deviations
- M1 signal shape: a three-valued `ScanKind` from `last_scan_kind()`, not the suggested `is_replay() -> bool`. The third value (`MeasuredAfterReset`) is what lets D2 fall out of the same seam instead of a second trait method. Same effect for M1.
- `every_fallback_family_failing_still_says_why_traceroute_is_in_use` (round 1, C3): its 80x24 assertion inverted. It asserted the reason on the bottom border; the wrapped header now shows it, and the test asserts the header names the reason and the border carries no note.

### Tradeoffs
- The scanner reports its last scan's kind through a side method vs a new `scan()` return type: an additive default keeps every scanner and test stub compiling unchanged. The cost is a little state on the traceroute scanner, written and read by the one `run` loop that drives it.
- Reset on every switch to the fallback vs only on a switch from a streaming mtr: on the first scan there is nothing retained, so the reset is a no-op, and one rule is simpler than two.
- Wrap the header only with no route retained vs always: with a route, the fallback fit fixture fills all 8 inner rows, so a wrapped header would push Duration off (the round 1 C3 constraint). With no route the rows are free.

### Bite checks (2026-11-10; each break applied by a script in the session scratchpad, full `cargo test --lib`, file restored from a backup and confirmed identical with `filecmp`)
- Replay recorded as usual: 4 failed (`replayed_scans_are_not_recorded`, `replayed_failure_keeps_the_original_failure_and_its_time`, `a_measurement_after_replays_is_recorded`, `back_to_back_fallback_scans_record_once`).
- Status not restored after a replay: 3 failed (`replayed_scans_are_not_recorded`, `replayed_failure_keeps_the_original_failure_and_its_time`, `back_to_back_fallback_scans_record_once`).
- `MeasuredAfterReset` not cleared: 3 failed (`failure_measured_after_reset_drops_the_retained_result`, `success_measured_after_reset_starts_history_over`, `failing_fallback_after_mtr_vanishes_drops_the_mtr_route`).
- Deadline guard removed: 1 failed (`a_timed_out_scan_is_recorded_even_when_reported_as_a_replay`).
- Traceroute never reports `Replayed`: 1 failed (`back_to_back_fallback_scans_record_once`). Never reports the reset: 1 failed (`failing_fallback_after_mtr_vanishes_drops_the_mtr_route`).
- Header never wraps: 2 failed (`every_fallback_family_failing_shows_the_whole_failure_at_80x24`, `every_fallback_family_failing_still_says_why_traceroute_is_in_use`). Header always wraps: 4 failed (`header_with_a_route_stays_one_row`, `fallback_route_fits_the_80x24_dashboard_with_destination_and_duration`, `fallback_reason_is_on_the_border_when_the_80x24_header_clips_it`, `a_long_fallback_reason_is_clipped_on_the_border`).
- Border note ignores the wrap: 1 failed (`every_fallback_family_failing_still_says_why_traceroute_is_in_use`).

### Open questions
None.
