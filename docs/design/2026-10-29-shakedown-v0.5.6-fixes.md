# Design Document: Shakedown Fixes After v0.5.6

**Author:** Scott Idler
**Date:** 2026-10-29
**Status:** Implemented
**Review Passes Completed:** 5/5

## Summary

A tui-test shakedown of the installed v0.5.6 binary across 12 target types, plus Scott's own run against `www.tatari.tv`, found 11 defects. Three hit the core picture:
- traceroute never reaches CDN-fronted hosts
- the connectivity sparkline cannot be read
- WHOIS fails for subdomains and for every TLD outside a stale hard-coded RDAP table

The rest are failures that hide their reason or mislabel what happened, plus text that clips in narrow terminals. This doc fixes all 11 in the current architecture.

## Problem Statement

### Background
- v0.5.5 shipped `docs/design/2026-10-29-runtime-bug-fixes.md`; v0.5.6 shipped `docs/design/2026-10-29-whois-fallback.md`.
- Scott asked for a fresh shakedown after v0.5.6 ("rerun the tui testing find what else is broken"). His mid-run screenshots raised items 1, 2 and 3.
- Evidence: the 12 captures and the debug log from the shakedown session. Measurements are pasted below. Anchors are `path:line` at `83a5e65`.

### Problem

| # | Defect | Root cause | Evidence | Raised by |
|---|---|---|---|---|
| 1 | Traceroute `✗ unreached` for Vercel, Azure and AWS hosts | `src/scan/traceroute.rs:207-217` runs `traceroute` with no method flag, so it sends UDP probes, which those edges drop. "Unreached" is then shown as a failure, when it means the target never answered | to 216.150.1.193, UDP probes time out on all 20 hops; `traceroute -I` reaches it at hop 10-18 | Scott (screenshot) |
| 2 | Sparkline is unreadable | no `.max()`, so it auto-scales, and there is no ms scale (`src/tui/connectivity.rs:500-503,546-549`). Data fills left to right, so the newest bar sits mid-pane until the buffer fills. Failed pings are dropped (`:195-240`), so gaps vanish from the time axis. `as_millis()` truncates sub-ms pings to 0 (`src/tui/sparkline.rs:47-48`). Fixed `Length` rows (`connectivity.rs:432-442`) leave no sparkline row at 80x24 | screenshot; at 80x24 no sparkline is drawn | Scott (screenshot) |
| 3 | WHOIS shows `Status: retrieved` next to `Source: Failed` | when RDAP and WHOIS both fail, `scan_whois` returns `Ok` with `DataSource::Failed` (`src/scan/whois.rs:135-158`), so the status is `Complete` and `status_label` prints "retrieved" (`src/tui/whois.rs:74`) | screenshot of `www.tatari.tv` | Scott (screenshot) |
| 4 | WHOIS looks up the full hostname | `whois.rs:76` uses `target.domain`, which is the URL host or the raw input | `rdap.nic.tv/domain/www.tatari.tv` gives 404; `tatari.tv` gives 200 | Scott (screenshot) |
| 5 | RDAP fails for most TLDs | hard-coded table at `whois.rs:258-268`. The default `rdap.iana.org` serves only IANA's own objects. `net` points at verisign's `/com/` path, `rdap.nic.io` does not connect, and `rdap.afilias.net` (info, biz) is dead | `.dev`: 404 from rdap.iana.org, 200 via rdap.org; IANA `dns.json` has 592 services | shakedown |
| 6 | HTTP failure hides its reason | the aggregate message has no cause (`src/scan/http.rs:789-799`); `classify_http_error` stores the outer context string, not `root_cause` (`:160-167`) | log `request_failed ... error=operation timed out`; pane says `All HTTP attempts failed for target` | shakedown |
| 7 | Failure status printed twice | extra `📊 Status: scan failed` lines in `src/tui/http.rs:239-244`, `src/tui/traceroute.rs:150-156`, `src/tui/ports.rs:271-276` | captures: `port`, `dead`, `local` | shakedown |
| 8 | Ping says "disconnected" when a host only drops ICMP | `calculate_state` gives Disconnected (`connectivity.rs:87-108`), labelled "disconnected" (`:463`). IPv6 hard-codes "network unreachable" (`:507`) | neverssl.com: HTTP 200 but ping "disconnected" | shakedown |
| 9 | No-IPv6-route is not named | traceroute aggregate prints `{:?}` (`traceroute.rs:583-586`), so the pane shows `IPv4=NoAddress`. `ping.rs:481` only matches "Network is unreachable". `failure_reason` prefers IPv4's `NoAddress` (`ping.rs:104-113`) | `2606:4700:4700::1111` on this host: `disconnected: no address`, `All traceroute protocols failed: IPv4=NoAddr...`; `ping -6` gives `Cannot assign requested address` (os error 99) | shakedown |
| 10 | Text clips mid-word in narrow terminals | only `src/tui/http.rs:279` wraps; every other pane renders unwrapped | Scott's ~108-col screenshot: `Protocol: IPv4+IPv6 (Pre`; at 80x24 nearly every line is cut | Scott (screenshot) |
| 11 | Port labels and IPv6 ping on a domain with no AAAA | `get_service_name` (`src/scan/port.rs:464-486`) has no 8080. IPv6 ping pings the hostname when there is no AAAA and fails `Address family for hostname not supported` instead of `NoAddress` (`target.rs:490`) | 1.1.1.1 `8080/tcp (unknown)`; debug log | shakedown |

### Goals
- Traceroute reaches hosts that answer ICMP. When the target stays silent it says so, not "failed".
- The sparkline shows time direction, scale and failed samples at any terminal size where the pane is visible.
- Every failure names its cause in the pane: HTTP, ping, traceroute, WHOIS, and no-IPv6-route.
- WHOIS finds the registrable domain and the right RDAP server for any TLD in IANA's bootstrap.
- A line too long for its pane ends in `…` instead of being cut mid-word.

### Non-Goals
- Excluded: TCP traceroute (`-T`). It needs root; record it as the remaining gap for ICMP-silent hosts (neverssl on AWS).
- Excluded: letting HTTP success change the ping label. Scanners stay independent; each label is honest on its own.
- Excluded: making existing network-hitting tests hermetic (carried over from `2026-10-29-runtime-bug-fixes.md`). New tests use local fakes.
- Lifted: the runtime-bug-fixes non-goal "emoji width handling" is lifted for `fit_line` only. It measures display width with ratatui's `Line::width()`. No hand-padding changes.

## Proposed Solution

### Overview
Fix forward at the cited seams. Two pieces of fast-changing data move out of the binary into a fetched, cached file: the RDAP bootstrap and the public suffix list. Two shared helpers kill a defect class each: a route classifier and `fit_line`.

### Architecture
- **Traceroute (#1):**
  - `traceroute_args(os, family, ...)` adds `-I` (ICMP echo). It is documented for Linux `traceroute`/`traceroute6` and macOS `traceroute`/`traceroute6`.
  - If stderr contains `You do not have enough privileges to use this traceroute method`, retry once with UDP. Never retry on "unreached", which would double a 15s silent run into the 30s deadline.
  - The pane labels a silent target `✗ target silent (last reply: hop N)`, not `unreached`. When no hop replied at all it reads `✗ target silent (no hop replied)`, never `hop 0`.
  - A run that hits the scan deadline renders through the existing `failure_text` as `failed: timed out after 30s`. The 15s for an all-`*` run is a measurement, not a bound.
  - The privilege fallback is Linux-only. macOS `traceroute` is setuid root, so `-I` does not hit an unprivileged-socket error there (unverified: no macOS host).
- **Sparkline (#2):**
  - `SparklineData` stores one `(Instant, Option<u64>)` per ping cycle, in microseconds. `None` means the ping failed.
  - A successful sample too small to draw is floored to one eighth of a row, because ratatui's bar height is `value * rows * 8 / max` (`sparkline.rs:388`). So any reply shows.
  - Render with `RenderDirection::RightToLeft`, newest first, so the newest bar is at the right edge.
  - `.max()` is the smallest step at or above the visible maximum, from 1/2/5/10/20/50/100/200/500/1000/2000/5000 ms. 5000 is the ping timeout (`ping.rs:8-9`), so no sample exceeds it.
  - The latency color thresholds (50ms, 150ms) are carried over to µs.
  - `absent_value_symbol` in red marks a failed sample.
  - The title line reads `IPv4 12ms avg 11ms │ scale 0-20ms │ ← 60s`. The span is measured from the oldest to the newest visible sample timestamps, not columns × interval, because a failed cycle can take up to the 5s timeout.
  - Row heights come from `inner_area.height`:
    - Full mode needs `1 + 2 × families` rows: the status line, then a title row and at least one graph row per family. Extra rows go to the graphs.
    - Compact mode applies when there are fewer rows. Each family gets one row: its short label (`v4 12ms`) on the left and the sparkline in the remaining width.
    - At 80x24 the connectivity pane is 56x6 outside its border and 54x4 inside (`src/tui/layout.rs`), which fits the status line plus two compact rows.
- **WHOIS (#3, #4, #5):**
  - When both methods fail, `scan_whois` returns `Err("RDAP: <e>; WHOIS: <e>")`. `status_label`/`failure_text` then drive the header, and a failed refresh keeps the last good data. `DataSource::Failed` and `RiskIndicator::QueryFailed` are deleted.
  - Registrable domain:
    - Fetch the public suffix list from `https://publicsuffix.org/list/public_suffix_list.dat` and cache it at `~/.cache/scan/public_suffix_list.dat` for 24h.
    - Parse it as `publicsuffix::IcannList` (`cargo add publicsuffix`), the ICANN section only. The default `List` includes the PRIVATE section (`publicsuffix-2.3.0/src/lib.rs:211`), which would make `foo.github.io` the registrable domain and bring #4 back.
    - The pane shows `Domain: tatari.tv (from www.tatari.tv)`.
    - A stale cache is used over failing, with no age limit when a refetch fails.
    - With no cache and a failed fetch, WHOIS runs on the raw host and the pane shows `Domain: www.tatari.tv (suffix list unavailable: <e>)`. This degrades visibly instead of blocking a lookup v0.5.6 would have attempted.
    - The host is lowercased and converted to punycode with `idna` before the suffix lookup. `idna` is only transitive today, so `cargo add idna`.
    - A host with no registrable domain (`localhost`, a bare public suffix) returns `NotApplicable` with the reason `no registrable domain`, rendered gray like an IP target.
  - RDAP server:
    - Fetch `https://data.iana.org/rdap/dns.json` and cache it at `~/.cache/scan/rdap-dns.json` for 24h. The server sends `max-age=86400`.
    - Delete the `get_rdap_endpoint` table.
    - A TLD missing from the bootstrap skips RDAP with the reason `no RDAP service for .io`, and the WHOIS fallback still runs.
  - Both source URLs are fields on `WhoisScanner`, as `iana_server` is, so tests point them at local fakes.
  - A cold-cache fetch of either file counts against the 30s RDAP budget, not on top of it, so the 50s `deadline()` still holds.
  - Cache writes go to a temp file in the cache dir, then `rename`, so a concurrent `scan` never reads a half-written file.
  - A corrupt cache file is treated as missing and refetched.
  - If the cache dir is unwritable, the fetched data is used in memory and the write failure is logged.
  - The debug log records cache age, refresh failures, and when a fallback (stale cache or raw host) was used.
- **Failure reasons (#6, #7, #9):**
  - `classify_route_error(text: &str, family: Family) -> RouteError` in `src/scan/mod.rs`:
    - os error 101 (`Network is unreachable`) maps to `NoRoute(family)`.
    - os error 99 (`Cannot assign requested address`) maps to `NoRoute(Ipv6)` only when `family` is IPv6. On IPv4 it also means ephemeral-port exhaustion (`man 2 connect`), so it stays `Other`.
    - os error 113 (`No route to host`) is a remote condition. It maps to `Other("host unreachable")` and never renders "no route on this host".
  - HTTP keeps `root_cause` per family. The aggregate reads `IPv4: operation timed out; IPv6: no IPv6 route on this host`.
  - Traceroute: add a `Display` for `TracerouteStatus`. Leave `NoAddress` families out of the aggregate. No `{:?}` in user text.
  - `PingResult::failure_reason` prefers a family that was attempted over `NoAddress`.
  - Delete the three duplicate `📊 Status: scan failed` blocks.
- **Ping labels (#8):**
  - `PingStatus::Failed` carries `PingFailure { NoReply, NoRoute, Other(String) }`, set where the ping output is classified, not by string-matching in the TUI.
  - Labels: `no echo reply`, `no IPv6 route on this host`, `failed: <reason>`.
  - The overall status `no ping reply` replaces `disconnected`, and "network unreachable" is used only for `NoRoute`.
- **Clipping (#10):** `fit_line(Line, width) -> Line` in `src/tui/text.rs` truncates across spans, measured by display width. It keeps each span's style up to the cut and ends in `…`. Width 0 renders nothing and width 1 renders `…`. A wide glyph that straddles the cut is dropped, never split.
  - Applied to every pane's identifier lines (domains, URLs, locations, ciphers, IPs).
  - Failure and status-reason lines wrap only in non-scrolling panes. DNS, Security and Traceroute scroll by logical line, so they get `fit_line` everywhere.
- **Small (#11):**
  - `8080 => "http-alt"`.
  - IPv6 ping on a domain with no AAAA returns `NoAddress` without spawning ping. The guard is ping-local, in `src/scan/ping.rs` before `network_target_for_protocol` (`target.rs:340`). That shared function is left unchanged, because TLS also calls it.

### Data Model
- `SparklineData`: `VecDeque<Option<u64>>` (µs), capacity unchanged (200).
- `PingStatus::Failed(PingFailure)` with `enum PingFailure { NoReply, NoRoute, Other(String) }`.
- `enum RouteError { NoRoute(Family), Other(String) }` in `src/scan/mod.rs`.
- `WhoisResult`: add `queried_domain: String` (the registrable domain). `domain` stays the target host. Delete `DataSource::Failed` and `RiskIndicator::QueryFailed`.
- `WhoisScanner`: add `rdap_bootstrap_url`, `psl_url`, `cache_dir`.

### API Design
```rust
// scan/traceroute.rs
fn traceroute_args(target_os: &str, ipv6: bool, wait: u64, max_hops: u8, probes: u8, use_icmp: bool, target: IpAddr) -> (&'static str, Vec<String>);
// scan/mod.rs
fn classify_route_error(text: &str, family: Family) -> RouteError;
// scan/whois.rs
async fn registrable_domain(&self, host: &str) -> eyre::Result<String>;
async fn rdap_base_url(&self, tld: &str) -> eyre::Result<Option<String>>;
// tui/text.rs
fn fit_line(line: Line<'_>, width: u16) -> Line<'_>;
```

### Implementation Plan

Each phase: one commit, `otto ci` green. Each new test is shown failing with its fix undone.

#### Phase 1: Small fixes
**Model:** sonnet
- 8080 http-alt; delete the three duplicate status blocks (#7); IPv6 ping returns `NoAddress` when there is no AAAA (#11).
- **Success criteria:**
  - `get_service_name(8080) == "http-alt"`.
  - Failed renders of the HTTP, Traceroute and Ports panes each contain `Status:` exactly once.
  - The ping test for a domain with no AAAA asserts `NoAddress` with no child process spawned.

#### Phase 2: WHOIS failure is an error
**Model:** sonnet
- #3. Return `Err` on total failure; delete `DataSource::Failed` and `QueryFailed`; update `src/tui/whois.rs`, `src/pretty.rs` and the tests.
- **Success criteria:**
  - `Scanner::scan` with RDAP and WHOIS both pointed at failing local fakes leaves the WHOIS state `Failed`.
  - Its pane render contains `failed: RDAP` and no `retrieved`.
  - `--no-tui` output for it contains `❌ WHOIS:`.

#### Phase 3: Route classifier and failure reasons
**Model:** opus
- #6, #9: `classify_route_error`, per-family HTTP `root_cause`, traceroute `Display`, `failure_reason` ordering.
- **Success criteria:**
  - Classifier table test: 99 on IPv6 gives `NoRoute(Ipv6)`; 99 on IPv4 gives `Other`; 101 gives `NoRoute(family)`; 113 gives `Other("host unreachable")`.
  - An HTTP render of a timeout contains `operation timed out`.
  - A traceroute render of the IPv6-literal no-route fixture contains `no IPv6 route on this host`, and neither `NoAddress` nor `Failed(`.

#### Phase 4: Honest ping labels
**Model:** sonnet
- #8: `PingFailure`, labels.
- **Success criteria:** a no-reply fixture renders `no echo reply` and never `disconnected` or `network unreachable`; a NoRoute fixture renders `no IPv6 route on this host`.

#### Phase 5: Traceroute over ICMP
**Model:** opus
- #1: `traceroute_args` with `-I`, the privilege-text UDP fallback, and the `target silent` label.
- **Success criteria:**
  - The args test contains `-I` for Linux and macOS.
  - A fake runner returning the privilege stderr triggers exactly one UDP retry.
  - A render of a silent-target result contains `target silent (last reply: hop`.

#### Phase 6: Registrable domain and RDAP bootstrap
**Model:** opus
- #4, #5: PSL and `dns.json`, fetched and cached for 24h, injected URLs, table deleted.
- **Success criteria:**
  - Against local fake PSL and `dns.json` servers:
    - `www.tatari.tv` maps to `tatari.tv`, `a.b.co.uk` to `b.co.uk`, and `foo.github.io` to `github.io` (ICANN-only).
    - `.dev` maps to the fake's RDAP URL, and `.io` to `no RDAP service for .io` with the WHOIS fallback still attempted.
    - With the PSL fake down and no cache, the lookup runs on the raw host and the result carries `suffix list unavailable`.
  - A second lookup within 24h makes no fetch.

#### Phase 7: Readable sparkline
**Model:** opus
- #2: Option samples in µs, `RightToLeft`, stepped `.max`, absent symbol, scale and span labels, height-driven layout.
- **Success criteria:**
  - `render_pane(connectivity, 56, 6)`, the pane's size in an 80x24 terminal, contains sparkline glyphs for both families in compact mode.
  - A 500µs sample at `max` 1ms in one row renders a non-blank bar.
  - The newest sample is in the rightmost column.
  - A failed sample renders the absent symbol, and the title contains `scale 0-`.

#### Phase 8: fit_line across panes
**Model:** opus
- #10.
- **Success criteria:**
  - Per pane, a fixture with a known long value renders the exact expected prefix followed by `…`, at the widths that pane gets in 80x24 and 108x40 terminals. The assertion uses the source text, not the already-clipped buffer.
  - `fit_line` unit tests cover truncation across spans, width 0, width 1, and a wide glyph at the cut.
  - `Protocol:` lines that fit are unchanged.

#### Phase 9: Implementation audit fixes
**Model:** opus
- From implementation audit round 1: two must-fix, two cheap-win.
- HTTP redirect rows (src/tui/http.rs): `<code> <from> → <to>` on one row when it fits the pane width, the two-row form only when it does not, each row fit.
- WHOIS total failure (src/scan/whois.rs `scan_whois`): when the suffix list was unavailable and RDAP and WHOIS both fail, the error reads `RDAP: <e>; WHOIS: <e> (suffix list unavailable: <e>)`, so the pane's `failed:` header names it.
- PSL parse (`parse_suffix_list`): a list without `===BEGIN ICANN DOMAINS===` is corrupt, so it is neither used nor cached, and it is refetched.
- Fetch diagnostics (`CachedSource::load`, src/scan/whois/cache.rs): the outer timer runs 1s past reqwest's request timeout, still capped by the RDAP deadline, so reqwest's classified error is what normally logs.
- **Success criteria:**
  - At the 200x55 HTTP pane size (50x19), the audit's three fixtures (1 redirect and 7 issues, 2 tatari.tv redirects and 5 issues, 4 short redirects and 4 issues) show every issue name, and each redirect sits on one row.
  - With the PSL fake down, no cache, and RDAP and WHOIS fakes failing, the error keeps its `RDAP: ...; WHOIS: ...` prefix and the pane render contains `suffix list unavailable`.
  - `parse_suffix_list` on a PRIVATE-only list is an error, and a fetched PRIVATE-only list is not cached.
  - A hung fetch with the deadline far away fails with reqwest's `timeout` class, not `deadline`, and the outer timer never runs past the deadline.

## Acceptance Criteria

Live checks run the installed binary: `tui-test run --session ac --cols 200 --rows 55 -- scan <target>`, wait with `tui-test --session ac expect text "zz-never" --timeout 55000` (expected exit 1, used only as a wait; 55s covers the 50s WHOIS deadline), then the check, then `tui-test close --all`.

- [ ] **AC1** `www.tatari.tv`:
  - `tui-test --session ac expect text "Domain: tatari.tv"` exits 0.
  - `tui-test --session ac expect text "Source: RDAP"` exits 0.
  - `tui-test --session ac expect text "✓ reached"` exits 0.
  - The `✓` matters: a bare `reached` also matches `unreached`.
  - Observed on main (v0.5.6, 83a5e65): 1, 1, 1.
- [ ] **AC2** `web.dev`: `tui-test --session ac expect text "Source: RDAP"` exits 0.
  - Observed on main: 1.
- [ ] **AC3** `https://example.com:8443`: `tui-test --session ac expect text "operation timed out"` exits 0, and `expect text "scan failed" --not` exits 0.
  - Observed on main: 1, 1.
- [ ] **AC4** `neverssl.com`: `tui-test --session ac expect text "disconnected" --not` exits 0, and `expect text "no echo reply"` exits 0.
  - Observed on main: 1, 1.
- [ ] **AC5** `google.com` at `--cols 80 --rows 24`: `tui-test --session ac expect text "[▁▂▃▄▅▆▇█]" --regex` exits 0.
  - Observed on main: 1.
- [ ] **AC6** `1.1.1.1`: `tui-test --session ac expect text "8080/tcp (http-alt)"` exits 0.
  - Observed on main: 1.

## Resolved Decisions
- 2026-10-29: PSL and the RDAP bootstrap are fetched and cached, not compiled in. Both change faster than the code (`rules/taste.md`, decompose along change frequency). The research brief had recommended the compiled-in `psl` crate; overridden for consistency with the RDAP choice.
- 2026-10-29: IANA `dns.json`, not the `rdap.org` redirector. It is the authoritative source, and it avoids a third-party hop.
- 2026-10-29: UDP fallback only on the privilege error, never on "unreached". It keeps a silent run inside the 30s deadline.
- 2026-10-29: Ping and HTTP stay independent. No cross-scanner label coupling.
- 2026-10-29, panel round 1 (Gemini + Codex): 4 must-fix and 8 cheap-win folded in:
  - PSL cold-start degrades to the raw host and stale cache is preferred; ICANN-only list; sparkline compact mode at 80x24; family-aware errno mapping.
  - Sub-ms floor, steps past 1000ms, timestamp-based span label; `idna` as a direct dependency; ping-local #11 guard; `fit_line` across spans; µs color thresholds; 55s AC wait; scoped AC3.
- 2026-10-29: the 3 deferred items are folded in, since each is cheap: cache diagnostics in the debug log, the Linux-only privilege fallback note, and the unwritable-cache rule.
- 2026-10-29: rejected staff's bounded UDP retry on a silent ICMP target. No host that ignores ICMP but answers UDP has been observed, so the retry is premature. The panel agreed.
- 2026-10-29: rejected extra cache-concurrency scaffolding; temp file plus rename already covers it. The panel agreed.
- 2026-10-29: the compiled-in `psl` crate stays rejected (architect re-raised it). Visible degradation to the raw host covers the cold start, and fetched data keeps the change-frequency rule.
- 2026-10-29: WHOIS `Source:` renders directly under `Domain:`, so a long NS or status list cannot push it below the pane (AC2 at 200x55). Scott's ruling.
- 2026-10-29, implementation audit round 1 (Gemini + Codex): 2 must-fix and 2 cheap-win folded in as Phase 9; connect_timeout on RDAP and the OS-agnostic privilege fallback deferred. Synthesis: `~/.cache/review-panel/runs/4HhtOXvO/synthesis.md`.

## Alternatives Considered

### `rdap.org` for every TLD
- **Pros:** no cache, one URL.
- **Cons:** third-party redirector in the path; returns 404 for `.io` anyway.
- **Why not chosen:** the IANA bootstrap is the source rdap.org itself reads.

### Compiled-in `psl` crate
- **Pros:** no fetch, no failure mode.
- **Cons:** a new suffix needs a rebuild and release.
- **Why not chosen:** change-frequency rule; consistency with the RDAP bootstrap.

### `.wrap()` on every pane
- **Cons:** breaks the logical-line scroll math in DNS, Security and Traceroute.
- **Why not chosen:** `fit_line` keeps one rendered row per logical line.

## Technical Considerations

### Dependencies
- New: `publicsuffix` and `idna` as direct dependencies (`cargo add`). `idna` is already in `Cargo.lock`.
- New runtime fetches: `publicsuffix.org` and `data.iana.org`, at most once per 24h, cached in `~/.cache/scan/`.

### Testing Strategy
- Unit tests at each pure seam: args builder, classifier, step function, `fit_line`.
- `render_pane` tests per pane.
- Local fake servers for PSL, `dns.json`, RDAP and WHOIS. Every accept and read is bounded by a timeout.
- Live acceptance criteria after release.

### Rollout Plan
- Single repo. `scan` has no branch protection, so the release is a fast-forward of `main` plus `bump release`, as in the last two releases.

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| ICMP traceroute refused on hosts without `ping_group_range` | Med | Low | UDP fallback on the privilege text |
| PSL or bootstrap fetch fails at first run with no cache | Low | Med | loud WHOIS error naming the source; RDAP-less TLDs still use the WHOIS fallback |
| `fit_line` width differs from the terminal's emoji rendering | Med | Low | measured with `Line::width()`, which is unicode-width; same metric ratatui uses for layout |

## Open Questions

None.

## Review Pass Log

- Pass 1 (draft): 11-row problem table from the research brief and the shakedown; 8 phases.
- Pass 2 (correctness):
  - AC1 asserted `retrieved --not`, which contradicts a working WHOIS; replaced with `Source: RDAP`.
  - `expect "reached"` matched `unreached`, a false pass on main; now `✓ reached`.
  - The Phase 3 `rg` criterion could not be checked mechanically; now a render assertion.
- Pass 3 (clarity): the live-check harness is stated once above the criteria.
- Pass 4 (edge cases): fetch time counted inside the RDAP budget; atomic cache writes; corrupt cache treated as missing; IDN hosts converted to punycode; hosts with no registrable domain.
- Panel round 1: see Resolved Decisions. Synthesis: `~/.cache/review-panel/runs/2C5Ihipf/synthesis.md`.
- Pass 5 (excellence): every acceptance criterion run against v0.5.6; all fail there, as they should.

## References
- `docs/design/2026-10-29-runtime-bug-fixes.md`, `docs/design/2026-10-29-whois-fallback.md`
- IANA RDAP bootstrap: https://data.iana.org/rdap/dns.json
- Public suffix list: https://publicsuffix.org/list/public_suffix_list.dat
