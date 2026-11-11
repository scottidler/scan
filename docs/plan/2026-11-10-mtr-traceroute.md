# Design Document: mtr-style continuous traceroute

**Author:** Scott Idler
**Date:** 2026-11-10
**Status:** Implemented
**Review Passes Completed:** 5/5 (see Pass Log)
**Review Panel:** round 1 folded in (see Review Panel Round 1)

## Summary

scan's traceroute is a snapshot: one `traceroute` run every 5 minutes, 3 probes per hop. The ask is mtr: a route that keeps probing and shows running per-hop stats (Loss%, Snt, Last, Avg, Best, Wrst, StDev). This plan drives `mtr --raw` as a long-lived child, folds its stream into per-hop counters in the scan layer, and keeps the existing `traceroute` path as the visible fallback when mtr cannot run.

## Problem Statement

### Background

- `src/scan/traceroute.rs`:
  - `TRACEROUTE_INTERVAL_SECS = 5 * 60`.
  - `traceroute_args` builds `traceroute -n [-I] -w 3 -m 30 -q 3 <ip>`; an ICMP privilege refusal (`icmp_refused`) retries over UDP.
  - `parse_traceroute_output` fills `TracerouteData { hops: Vec<TracerouteHop>, destination_reached, total_hops, max_hops, target_ip, scan_duration, ipv6 }`.
  - `TracerouteHop { hop_number, responses, best_rtt, avg_rtt, worst_rtt, packet_loss }` covers the 3 probes of one run. Nothing carries across runs.
  - `TracerouteHop::is_silent`, `TracerouteData::last_reply_hop`, `destination_hop` and `silent_hops` all read `responses`.
  - `Protocol::Both` traces IPv4 and IPv6 with `tokio::join!`, one target IP per family (`Target::primary_ip_for_protocol`). Each family's outcome goes through `family_outcome`, which runs failures through `classify_route_error`.
- `src/scanner.rs` `Scanner::run` (default method, no scanner overrides it):
  - ticks on `interval()`, calls `scan()` under `deadline()` (30s default), stores one result per call via `record_outcome`
  - a protocol change (`p` key) drops the in-flight scan, runs `clear_for_protocol_change`, rescans at once
  - `next_delay(result)` overrides the wait after a successful result only (`failed_scan_ignores_next_delay` pins that)
- `src/scan/mod.rs` `classify_route_error(text, family)` returns `NoRoute(family)` for errno 101 (and 99 on IPv6), `Other("host unreachable")` for errno 113, and `Other(text)` for anything else.
- Child processes go through `kill_on_drop_command` (`src/scan/mod.rs`), so a dropped scan never leaves `ping`/`traceroute` behind.
- Rolling ping history lives on the TUI side (`ConnectivityPane::ingest`, `src/tui/connectivity.rs`), so `--no-tui` never sees it.
- `--no-tui` prints one traceroute line (`src/pretty.rs`), reprinted every 5s by `main.rs`.

### Problem

- A coworker in the scan feedback thread (2026-11-10): "traceroute in the style of mtr would be dope (basically a ping + traceroute, constantly running a traceroute)".
- Today a route problem that comes and goes (a lossy hop, a flapping path) is invisible: the pane shows one 3-probe sample, up to 5 minutes old.

### Goals

- G1 (coworker): the route keeps probing while scan runs, about once per second per hop.
- G2 (coworker, "in the style of mtr"): every hop shows mtr's columns: Loss%, Snt, Last, Avg, Best, Wrst, StDev, accumulated since the trace started.
- G3 (follows from G2, mtr shows it): a hop that answers from more than one address (ECMP, equal-cost multipath load balancing) lists every address seen.
- G4 (taste, degrade visibly): when mtr cannot run, scan falls back to today's `traceroute` path and the pane says why.
- G5 (taste, siblings behave identically): `--no-tui` reads the same accumulated stats the TUI shows.

### Non-Goals

- **A native ICMP prober** (raw or unprivileged DGRAM socket in Rust). Excluded. mtr already solves probing; every other scan prober shells out (`ping`, `traceroute`, `whois`). See Alternatives.
- **Making mtr a hard dependency.** Excluded. scan ships for Linux and macOS (`.github/workflows/release.yml`); a missing or unusable mtr falls back.
- **A config key or flag to pick the engine.** Parked. Auto-detect covers the ask. Revisit if someone with mtr installed wants the snapshot instead.
- **Reverse DNS names per hop** (mtr without `-n`). Excluded. Today's traceroute runs `-n`; this keeps parity.
- **UDP / TCP probe modes** (`mtr -u`, `-T`). Excluded. mtr's default is ICMP echo, matching today's `traceroute -I`.
- **Per-hop latency graphs.** Excluded. Not asked.
- **Per-address stats inside an ECMP hop.** Excluded. mtr's own report shows aggregate stats per hop; G3 lists the addresses only.
- **Changing the fallback's 5-minute cadence.** Excluded. Fallback behavior stays as shipped (see Scheduling for how the 5 minutes is now kept).

## Proposed Solution

### Overview

1. On the first `scan()`, `TracerouteScanner` tries to start one `mtr --raw` child per traced family.
2. A reader task per child parses each raw line and folds it into a per-hop accumulator behind a mutex.
3. The scanner's interval drops to 1s. Each `scan()` returns a snapshot of the accumulators as an ordinary `TracerouteResult`, so the default `Scanner::run` loop, `record_outcome`, the TUI and `pretty.rs` keep working unchanged in shape.
4. If mtr cannot run, the scanner switches to the existing `traceroute` path and marks the result with the reason. The scanner throttles itself, so the 1s tick never reruns `traceroute` or respawns mtr every second.

One additive `Scanner` change: a default method, `last_scan_kind()`, returning `ScanKind::Measured` for every other scanner. The traceroute scanner reports a throttled fallback replay as `Replayed`, which `Scanner::run` does not record, and the scan that switches to the fallback as `MeasuredAfterReset`, which drops the retained mtr route first (see Scheduling). No new crate.

### Phase 0 evidence (spike, run 2026-11-10 on ripr, Linux, mtr 0.95)

Run before drafting; this is the environmental proof the design rests on.

- `/usr/bin/mtr-packet` carries `cap_net_raw=ep`, so mtr runs unprivileged.
- `mtr --raw -n -c 2 1.1.1.1` exits 0 and streams line by line (lines arrive spread over the run, not at exit). Excerpt:
  ```
  x 0 33000
  h 0 10.10.10.1
  h 0 10.10.10.1
  p 0 404 33000
  ...
  x 5 33005
  x 6 33006
  h 6 108.162.243.11
  h 6 108.162.243.11
  p 6 6323 33006
  x 7 33007
  h 7 1.1.1.1
  h 7 1.1.1.1
  p 7 5887 33007
  x 8 33008
  h 8 1.1.1.1
  h 8 1.1.1.1
  p 8 6887 33008
  x 0 33009
  p 0 338 33009
  ...
  x 7 33016
  p 7 5350 33016
  ```
- Record grammar, as observed:
  - `x <hop> <seq>`: probe sent. `<hop>` is 0-based. `<seq>` starts at 33000 and is shared across hops.
  - `h <hop> <ip>`: the address answering at that hop changed (printed twice on first sight of an address, once when the hop flips back to an address it had before).
  - `p <hop> <rtt_us> <seq>`: reply to probe `<seq>`, RTT in microseconds.
  - No record marks a lost probe: `x 5 33005` with no `p` is the silent hop.
  - Cycle 1 probes one hop past the destination (`hop 8` repeats `1.1.1.1`); later cycles stop at the destination.
- **Cycle count (panel round 1):** with no `-c`, `mtr --raw -n 1.1.1.1` exits after 10 cycles (observed: 10 hop-0 `x` lines, 16s). `-c 0` exits with no output; `-c 2147483647` is rejected; `-c 1000000` streams. scan passes `-c 1000000` (about 11.5 days at 1 cycle/s) and respawns on exit (see Engine selection).
- ECMP: `mtr --raw -n -u -c 10 104.16.132.229` emitted 8 distinct `h 6 108.162.243.*` addresses over 10 probes, each `h` immediately before the `p` it belongs to. So a `p` belongs to the last `h` seen for its hop. This capture used `-u` (UDP); scan runs ICMP, which spreads less across ECMP paths, but the `h`/`p` grammar is the same.
- `mtr --raw -n -c 1 -i 0.5 1.1.1.1` prints `mtr: non-root users cannot request an interval < 1.0 seconds`. 1s is the floor unprivileged.
- `mtr -6` on ripr (no IPv6 route) prints `mtr: udp socket connect failed: Cannot assign requested address`, exit 1. `classify_route_error(.., Ipv6)` maps that to `NoRoute(Ipv6)`.
- After `mtr --raw -n 1.1.1.1 | head -3`, `pgrep -a mtr` prints nothing (exit 1): mtr dies of SIGPIPE once its reader is gone, and `mtr-packet` exits with it.
- Not verified: unprivileged mtr on macOS. The design does not depend on it: any non-network mtr failure falls back (G4). The shakedown records the macOS outcome.

### Architecture

```
scan() ──first call──> MtrSession::start(family, ip)  ── spawn ──> mtr --raw -n -4|-6 -m 30 -c 1000000 <ip>
   │                                                                  │ stdout lines
   │                                                     reader task: parse_line -> Accumulator::apply
   │                                                                  │
   └──every 1s──> session.snapshot() -> TracerouteData ───────────────┘
                     │
                     └─> ScanResult::Traceroute -> record_outcome -> TUI pane | pretty.rs
```

- **`src/scan/traceroute/raw.rs`** (new, pure): `parse_line(&str) -> Option<RawRecord>`, `RawRecord::{Sent, Host, Reply}`.
- **`src/scan/traceroute/accumulator.rs`** (new, pure): `Accumulator` folds `RawRecord`s into per-hop counters and emits `TracerouteData`.
- **`src/scan/traceroute/mtr.rs`** (new, I/O): `MtrSession` owns the child (`kill_on_drop_command`, `MTR_OPTIONS` removed from its environment so a user's mtr defaults cannot change the flags), the reader task, the shared `Accumulator`, the protocol it was started for, its last stderr line, and the time of the last stdout line.
- **`src/scan/traceroute.rs`**: `TracerouteScanner` gains `engine: Mutex<EngineState>`; `scan()` picks the engine and throttles; `interval()` returns 1s.
- **`src/scanner.rs`**: `ScanKind { Measured, MeasuredAfterReset, Replayed }` and the default `Scanner::last_scan_kind()`; `Scanner::run` records, resets then records, or skips by kind (Scheduling).

State lives in the scan layer, not the TUI. This deviates from the ping/connectivity precedent on purpose: mtr's columns are cumulative counters defined by the stream, and G5 needs `--no-tui` to print the same numbers. One owner, no second copy.

### Data Model

Extend the existing types; no parallel mtr type, so the pane and `pretty.rs` render one shape.

```rust
pub enum TraceEngine {
    /// Continuous: `cycles` probe rounds started since the session started.
    Mtr { cycles: u32 },
    /// Snapshot fallback; `reason` says why mtr is not in use.
    Traceroute { reason: String },
}

pub struct TracerouteData {
    // existing fields unchanged
    pub engine: TraceEngine,
}

pub struct TracerouteHop {
    // existing: hop_number, responses, best_rtt, avg_rtt, worst_rtt, packet_loss
    pub sent: u32,                         // settled probes (replied + lost)
    pub replied: u32,
    pub last_rtt: Option<Duration>,
    pub stddev_rtt: Option<Duration>,
    pub addresses: Vec<IpAddr>,            // every address seen, first-seen order
    pub current_address: Option<IpAddr>,   // the address of the latest reply
}
```

- **Helpers move to the aggregate fields** (panel round 1: an empty `responses` reads as silent):
  - `is_silent()` = `replied == 0`
  - `destination_hop()` follows the engine (implementation audit round 1, M2):
    - traceroute engine: the hop whose `addresses` contain `target_ip`, i.e. the target answered any of one run's 3 probes (the v0.6.4 rule). The parser's `destination_reached` uses the same check, so the two cannot disagree.
    - mtr engine: the hop whose `current_address == target_ip` (with trimming, the last hop). `addresses` is cumulative over the session, so an address seen once long ago does not count.
  - `last_reply_hop()` and `silent_hops()` keep their meaning through `is_silent()`
- The traceroute parser fills the new fields from its 3 probes: `sent = 3`, `replied` = answered probes, `last_rtt` = last answered probe, `stddev_rtt` from the answered RTTs, `addresses` = distinct response IPs, `current_address` = last answering IP. `engine = Traceroute { reason }`. Existing traceroute output therefore keeps today's silent/destination answers.
- `responses` stays empty in mtr mode: it describes individual probes of one run, which a cumulative view does not have. Nothing reads it for silence or destination after this change.
- `Accumulator` per hop: the fields above plus `sum_us`, `sum_sq_us`, the pending seq set and a bounded recent-lost seq list (see rules).
- **StDev** is the sample standard deviation (n-1 denominator, as mtr reports), from `sum_us` and `sum_sq_us`; `None` under 2 replies. No sample buffer, so memory stays flat for a session of any length.

### Accumulator rules

- **Hop number:** raw hop + 1, so hop numbers match `traceroute`'s 1-based output.
- **Sent:** `x hop seq` settles every seq still pending for that hop as lost (by membership, not numeric order), then adds `seq` as pending.
- **Lost:** a settled seq goes to the hop's recent-lost list, capped at `LOST_RETRACT_WINDOW` (4) entries; older entries are final and dropped. A silent hop's state therefore stays bounded.
- **Reply:** `p hop rtt seq`:
  - if `seq` is pending, remove it and count a reply
  - if `seq` is in the recent-lost list, remove it, move one count from lost to replied (a reply slower than one cycle)
  - otherwise ignore it (stale, or a reused seq; logged at DEBUG)
  - a counted reply updates last/best/worst/sums, and sets `current_address` from the hop's latest `h`
- **Seq reuse:** mtr's seq wraps within a range above 33000 and is shared across hops, so a value repeats after tens of thousands of probes. Membership is checked only against a hop's pending seq and its last 4 lost seqs, so a wrapped seq cannot collide in practice.
- **Snt:** replied + lost. In-flight probes are excluded. A reply slower than one cycle is counted lost first and retracted when it arrives, so Loss% can briefly overstate a slow hop. Snt lags mtr's own count by at most one per hop.
- **Loss%:** lost / Snt.
- **Host:** `h hop ip` sets the hop's latest-seen address; appends `ip` to `addresses` if new. Duplicate `h` lines are idempotent.
- **Destination:** the lowest hop whose `current_address == target_ip`. Hops above it are dropped from the snapshot (removes cycle 1's past-destination probe, and follows a path that gets shorter). `destination_reached` = a destination hop exists. Hops with Snt 0 are left out.
- **Cycles:** count of `x` records for raw hop 0 (rounds started).
- **Unparseable line:** logged at WARN with the line, skipped.

### Engine selection and failure handling

- **Start:** first `scan()` per protocol spawns one `MtrSession` per family the protocol traces (`Both` -> v4 and v6, as today), with `mtr --raw -n -4|-6 -m 30 -c 1000000 <ip>` (`-m` = `MAX_TRACEROUTE_HOPS`, parity with traceroute). The IP is `Target::primary_ip_for_protocol`, fixed for the session. A family with no address reports today's no-address failure and starts no child.
- **First snapshot:** the first `scan()` on a new session waits until the first parseable line or `MTR_STARTUP_GRACE` (5s), whichever comes first, so it can tell "mtr broken" from "route still forming". Until any hop has Snt 1 or more, the pane shows `tracing route...`.
- **Engine scope:** one engine for the whole scanner, so the pane never mixes modes.

Every failure and what it does (panel round 1: "classifies via" picked no branch):

| Failure | Detected by | Effect on that family | Effect on the engine |
|---|---|---|---|
| `mtr` not on PATH | spawn `ErrorKind::NotFound` | n/a | fall back, reason `mtr not installed` |
| network condition: stderr mentions errno 101, 99 (IPv6) or 113 | `classify_route_error` returns `NoRoute`, or `Other("host unreachable")`, on the child's exit or, if it hangs, at `MTR_STARTUP_GRACE` (the hung child is killed) | `TracerouteStatus::Failed(<classified text>)`, as today's traceroute reports it | stays mtr; other family keeps streaming; that family retries after `MTR_RESPAWN_SECS` (5s) |
| child exits before any parseable line, any other stderr | exit status + captured stderr | n/a | fall back, reason `mtr: <first stderr line>` (`mtr exited <code>` when stderr is empty) |
| no parseable line within `MTR_STARTUP_GRACE`, stderr not a network condition | timer | n/a | fall back, reason `mtr: no output`; the first `traceroute` runs on the next scan so the grace does not eat its deadline |
| child exits after good output (the `-c` limit, or killed) | exit after at least one parseable line | keeps its counters | respawn after `MTR_RESPAWN_SECS`; pending and recent-lost seqs are cleared because the new child restarts seqs at 33000 |
| no stdout line for `MTR_STALL_SECS` (10s) | timer | `Failed("mtr stalled: no output for 10s")` | kill and respawn after `MTR_RESPAWN_SECS` |

- **Fallback is sticky** for the process. A protocol switch does not retry mtr.
- **Both families:** if one family fails and the other has data, the result is a success carrying that family's failed status. That is today's `TracerouteResult` behavior (per-family `TracerouteStatus`), kept as is.
- **Protocol change:** `scan(target, protocol)` compares against the session's protocol; on mismatch it drops the sessions (children killed by `kill_on_drop`) and starts fresh accumulators. `Scanner::run` has already cleared result and history via `clear_for_protocol_change`.
- **Shutdown:** a clean quit drops the sessions and `kill_on_drop` kills the children. `main.rs` installs no signal handler, so a SIGTERM skips the drop; mtr then dies of SIGPIPE on its next write (Phase 0 evidence). AC3 checks it.

### Scheduling

Panel round 1: `next_delay` applies only to successful results, and the 1s ticker would rerun a failing `traceroute` every second. So the scanner throttles inside `scan()` instead of relying on `next_delay`:

- **mtr engine:** `scan()` returns the current snapshot (instant). Respawns happen only when `MTR_RESPAWN_SECS` has passed since the last attempt for that family.
- **traceroute engine:** `scan()` runs `traceroute` only when `TRACEROUTE_INTERVAL_SECS` has passed since the last run (or none ran yet), and otherwise returns the last outcome, `Ok` or `Err`, as stored. A failing traceroute therefore runs at most once per 5 minutes, as today.
- A long traceroute run (up to the 30s deadline) can leave tokio interval ticks missed; the burst that follows hits the throttle and returns the stored outcome, so it costs nothing.
- `next_delay` is not used by this scanner.
- **Replays are not recorded.** A stored outcome returned by the throttle is not a new measurement. `scan()` reports it through `Scanner::last_scan_kind()` as `ScanKind::Replayed`, and `Scanner::run` skips `record_outcome` for it: status (put back from before `mark_running`), `last_updated` and history stay as the run that produced the outcome left them, so the pane shows the run's true age and a stored failure logs once, not every second. A scan dropped at its deadline is recorded as timed out whatever kind was reported.
- **The switch to the fallback resets.** The scan that switches the engine to `traceroute` reports `ScanKind::MeasuredAfterReset`, and `Scanner::run` drops the retained result, error and history before recording it. If mtr vanishes mid-run and the fallback then fails, the last mtr route does not stay on screen under the error.

### TUI

- **Grid** (`src/tui/traceroute.rs`, pane is 33% wide): `Status: mtr · 42 cycles` (or `Status: traceroute (mtr not installed)` in WARN), reach line, then one row per hop: hop, `current_address` (`+N` when more than one address was seen), `Loss%`, `Avg`. The mtr destination row has the same `+N` and colored Loss%. Silent runs still collapse to `3-9: no reply (7 hops)`.
- When the Status header clips the fallback reason (the 80x24 dashboard pane), the reason is drawn on the pane's bottom border, so G4 holds at any width. When every fallback family fails, the error names the reason too: `IPv4: no IPv4 route on this host (traceroute: mtr not installed)`.
- When no route is retained (every fallback family failed, or the first scan has not finished), the Status header wraps instead of being fitted to one row, so the whole failure is readable at 80x24; the border then carries no reason, since the header shows it.
- **Zoom:** per family, an mtr table: `Hop  Host  Loss%  Snt  Last  Avg  Best  Wrst  StDev`, then each extra ECMP address on its own indented row under its hop.
- Loss% colored by `BAD_LOSS_PERCENT = 10` (`src/tui/traceroute.rs`): `GOOD` at 0, `WARN` under 10%, `BAD` at 10% and above. The connectivity pane has no loss thresholds to reuse.

### `--no-tui`

`pretty.rs` traceroute line gains the engine and destination loss: `IPv4 8 hops, reached (6ms, loss 0%, 1 no reply, mtr 42 cycles)`, or `... (traceroute: mtr not installed)` on fallback.

### Implementation Plan

#### Phase 1: Raw parser, accumulator, extended types
**Model:** opus
- `src/scan/traceroute/raw.rs`: `parse_line`.
- `src/scan/traceroute/accumulator.rs`: rules above; `snapshot(target_ip, ipv6, max_hops) -> TracerouteData`.
- Add `TraceEngine` and the new `TracerouteHop` fields; the existing traceroute parser fills them; move `is_silent`, `destination_hop`, `last_reply_hop`, `silent_hops` onto the aggregate fields.
- Update every existing `TracerouteData` / `TracerouteHop` literal so the tree compiles (`src/tui/layout.rs` `traceroute_fixture`, the `src/tui/traceroute.rs` test fixtures, `src/pretty.rs` and `src/scan/traceroute.rs` tests). Rendering changes wait for Phase 3.
- Fixtures: the Phase 0 `-c 2` capture and the ECMP hop-6 capture, as string constants in the test module.
- **Success criteria:**
  - `cargo test scan::traceroute::accumulator` passes, asserting on the `1.1.1.1` fixture: hop 6 (raw 5) has Snt 1, Loss 100% (cycle 2's `x 5` settles cycle 1's probe); destination is hop 8 (raw 7); no hop 9 exists.
  - The same module asserts the ECMP fixture's hop 7 (raw 6) lists 8 distinct addresses in first-seen order, with Snt 10 and Loss 0%, and a late-reply test (`p` after the next `x`) asserts Loss drops back to 0%.
  - Every existing traceroute test passes unchanged in its assertions (the parser-filled fields keep today's silent and destination answers), and `otto ci` is green.

#### Phase 2: mtr session, engine selection, throttle
**Model:** opus
- `src/scan/traceroute/mtr.rs`: `MtrSession` (spawn with `-c 1000000`, `MTR_OPTIONS` removed, reader task, stall timer, stderr capture, respawn).
- `TracerouteScanner`: engine state, 1s `interval()`, throttle per Scheduling, protocol-mismatch restart, the failure table.
- `with_mtr_program` override for tests, mirroring `with_program`.
- **Success criteria:**
  - A fake-mtr script test (via `scan::testing::write_executable_script`, emitting raw lines with `sleep`, then exiting 0) asserts `sent` for hop 1 grows across two `scan()` calls, and that a second start appears in the fake's argument log after the exit (respawn, not fallback).
  - A missing-program test asserts the engine is `Traceroute { reason: "mtr not installed" }`, and that three back-to-back `scan()` calls run the fake traceroute once.
  - A fake mtr that prints `mtr: udp socket connect failed: Cannot assign requested address` and exits 1 under `Protocol::Both` leaves the engine on mtr, fails only IPv6, and the IPv4 fake keeps streaming; a protocol-change test asserts a fresh start with `-6` and `sent` restarted.

#### Phase 3: TUI pane and `--no-tui` line
**Model:** sonnet
- Grid and zoom rendering above; update `traceroute_fixture` and `tatari_route` fixtures to carry mtr-mode data.
- `pretty.rs` traceroute line.
- README: mtr is optional; scan falls back to `traceroute` and says why.
- **Success criteria:**
  - `cargo test tui::traceroute` passes, including the existing 80x24 fit test and the TUI/no-TUI silent-count parity test.
  - A zoom test asserts the `StDev` column header and one hop's values.
  - A `pretty` test asserts `mtr 3 cycles` and `loss 0%` in the line.

## Acceptance Criteria

- [ ] AC1: with mtr installed, `timeout 30 scan --no-tui 1.1.1.1 | rg TRACEROUTE` prints lines whose `mtr N cycles` count grows, and the last line still reads `mtr` (no fallback after mtr's own 10-cycle default would have ended it).
  - Observed on main: `✅ TRACEROUTE: IPv4 8 hops, reached (6ms, 4 no reply, 3001ms)`, identical every print (no engine, no cycle count). Cannot pass until Phase 3.
- [ ] AC2: with mtr hidden, the traceroute line reads `traceroute: mtr not installed`. Command: `d=$(mktemp -d); for b in ping traceroute traceroute6 whois; do ln -s "$(command -v $b)" "$d/"; done; timeout 12 env PATH="$d" ~/.cargo/bin/scan --no-tui 1.1.1.1 | rg TRACEROUTE` (`env` sets PATH for scan only, so `timeout` still resolves).
  - Observed on main: `✅ TRACEROUTE: IPv4 8 hops, reached (5ms, 4 no reply, 3003ms)` twice; no engine text. Cannot pass until Phase 3.
- [ ] AC3: after `timeout --foreground 10 scan --no-tui 1.1.1.1 >/dev/null; sleep 2`, `pgrep -c -f '^mtr --raw -n -[46] -m 30'` prints `0` (exit 1). `--foreground` signals scan alone, so mtr's exit has to come from scan going away; the anchored pattern ignores unrelated mtr processes and the shell running the check.
  - Observed on main: `0`, exit 1 (scan never starts mtr today; the criterion guards the new child).
- [ ] AC4: `otto ci` passes.
  - Observed on main (`7f4138d`): `✅ All CI checks passed!`, exit 0.

## Resolved Decisions

- 2026-11-10 (author, from Phase 0): mtr over a native prober. Native needs `IP_RECVERR`/`MSG_ERRQUEUE` handling and new socket deps; mtr runs unprivileged on Linux and already handles both families.
- 2026-11-10 (author): accumulate in the scan layer, not the TUI. Reason in Architecture.
- 2026-11-10 (author): lifetime-cumulative stats like mtr, reset on protocol change. Sums, not samples, keep memory flat.
- 2026-11-10 (author, tightened by panel round 1): clockless loss settling by set membership, with a bounded retraction window.
- 2026-11-10 (author): fallback is sticky for the process. A user who installs mtr restarts scan. Panel round 1 (architect) called this harsh; disposition: the harshness came from network errors falling back, which the failure table now keeps per family, so a sticky fallback only follows a broken or missing mtr.
- 2026-11-10 (author): one engine for both families. Panel noted it; author keeps it so the pane never mixes modes.
- 2026-11-10 (panel round 1, staff): the scanner throttles inside `scan()`; `next_delay` is not used.
- 2026-11-10 (author, implementation audit M1): a replayed fallback result is not recorded; `Scanner` gains an additive default replay signal.

## Alternatives Considered

### Override `Scanner::run` with a streaming loop
- **Description:** the traceroute scanner replaces the default loop, publishes from the reader task.
- **Pros:** results land the instant a cycle completes.
- **Cons:** re-implements protocol handling, cancellation and status bookkeeping that `run` and its tests already own.
- **Why not chosen:** a 1s snapshot through the unchanged loop gives the same cadence as mtr's own 1s floor with no duplicated control flow. Both panel seats agreed.

### `mtr -j` (JSON report)
- **Description:** run `mtr -j -c N` every few seconds and parse the report.
- **Pros:** mtr computes the columns; trivial parsing.
- **Cons:** prints only at exit, so it is a snapshot again; one host per hop, so ECMP is lost; counters restart every run.
- **Why not chosen:** fails G1 and G3.

### Native ICMP prober
- **Description:** send ICMP echo with per-probe TTL from a `socket2` DGRAM socket.
- **Pros:** no external tool; works where mtr is absent.
- **Cons:** time-exceeded replies arrive on the socket error queue (`IP_RECVERR`), unverified in Rust here; macOS differs; new deps; IPv6 path separate.
- **Why not chosen:** solves a problem mtr already solves, against the shell-out precedent. Parked; revisit if fallback turns out to be the common case.

### Keep state in the TUI (connectivity precedent)
- **Description:** scanner publishes per-cycle deltas; the pane accumulates.
- **Why not chosen:** `--no-tui` would never see the stats (G5), and two consumers would each need the accumulation logic.

## Technical Considerations

### Dependencies
- Runtime: `mtr` (optional). Linux packages ship `mtr-packet` with `cap_net_raw`. macOS unprivileged behavior unverified; fallback covers it.
- Build: none new. `tokio` (`process`, `io-util`) already in.

### Performance
- One mtr child per traced family, about 1 probe per hop per second. A snapshot clones at most 30 hops once per second into a 10-deep history. Per-hop state is counters plus at most 1 pending and 4 recent-lost seqs.

### Security
- mtr gets an IP literal and fixed flags; no shell, no user string reaches the command line; `MTR_OPTIONS` is stripped.
- No new privilege: scan never asks for root; an mtr that needs root falls back.

### Testing Strategy
- Pure parser/accumulator tests against captured mtr output.
- Fake-mtr scripts for session, respawn, fallback, route errors and protocol switching, same harness as the traceroute tests.
- Each new test broken once on purpose before being restored, as prior phases did.
- Shakedown: release build on ripr, TUI over tmux (`bin/snap.py`), a run past 15s to confirm no 10-cycle fallback, plus macOS if available.

### Rollout Plan
- Single repo, no cross-repo blast radius. Ships through the normal `bump release` path.

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| mtr on macOS needs root | Med | Low | Fallback with a visible reason (G4) |
| Raw format differs in other mtr versions | Low | Med | Unparseable lines logged; no parseable line within the startup grace -> fallback |
| Orphaned mtr after quit | Low | Med | `kill_on_drop`, SIGPIPE on signal death; AC3 |
| A network error text outside errno 99/101/113 triggers sticky fallback | Low | Med | Fallback reason shows the stderr; extend the table when one shows up |
| Target status icon flips to running every second | High | Low | Same as ping today, which also ticks at 1s through `Scanner::run` |

## Review Panel Round 1

Synthesis: `~/.cache/review-panel/runs/HYeF6tDb/synthesis.md`. Architect (Gemini) and Staff Engineer (Codex), both rc=0. 6 must-fix, 7 cheap wins, 5 demoted. Every must-fix was checked against ripr or the code before folding.

| Finding | Disposition |
|---|---|
| M1: no `-c` -> mtr exits after 10 cycles -> sticky fallback | Folded: `-c 1000000`, respawn on exit after good output; Phase 0 evidence; AC1 runs 30s |
| M2: `next_delay` ignored on errors -> 1s reruns | Folded: Scheduling section, throttle in `scan()` |
| M3: empty `responses` reads as silent | Folded: helpers move to `replied` / `current_address` |
| M4: route-error predicate undefined | Folded: failure table, errno 99/101/113 stay per family |
| M5: Phase 1 does not compile alone | Folded: Phase 1 updates every literal |
| M6: unbounded lost set, seq reuse | Folded: membership settling, 4-entry retraction window, clear on respawn |
| Destination by all addresses ever seen | Folded: `current_address` |
| Cycles defined two ways | Folded: rounds started |
| "never shows loss for a probe that may still answer" false | Folded: wording fixed in Snt rule |
| AC3 did not test the SIGPIPE path; pgrep too broad | Folded: `--foreground`, anchored pattern, re-observed on main |
| `MTR_OPTIONS` could change flags | Folded: stripped |
| StDev form unstated | Folded: sample (n-1) |
| One failed family still yields success | Folded as explicit: today's per-family status behavior, kept |
| Sticky fallback too harsh (architect) | Resolved Decisions entry |
| Rollback plan | Dropped: generic; a release revert is the rollback for any scan change |
| Cost of keeping every address | Deferred until observed (taste: make it be a problem first) |
| One engine for both families | Author's choice, Resolved Decisions |
| ECMP fixture used `-u` | Folded: one sentence in Phase 0 evidence |

## Open Questions

- (none)

## Pass Log

- Pass 1 (draft): shape from the research brief plus the Phase 0 spike on ripr.
- Pass 2 (correctness): ECMP fixture count fixed (8 distinct addresses, not 10); Phase 1 hop-6 loss math re-derived from the capture; SIGTERM shutdown path checked and documented with the observed SIGPIPE exit.
- Pass 3 (clarity): AC3 rewritten as a literal command; mtr argument list spelled out with `-m 30`.
- Pass 4 (edge cases): first-snapshot wait, no-address family, engine scope across families, 1s status flicker.
- Pass 5 (excellence): every acceptance command run on main and recorded; AC2's command fixed (`PATH=` before `timeout` hid `timeout` itself, `env PATH=` scopes it to scan).
- Panel round 1 folded in (table above); AC3 re-run on main with the new command.

## References

- mtr feedback thread, scan channel, 2026-11-10
- `docs/plan/2026-11-06-pane-split-and-feedback.md` (last pane plan)
- `src/scanner.rs`, `src/scan/mod.rs`, `src/scan/traceroute.rs`, `src/tui/traceroute.rs`, `src/pretty.rs`
