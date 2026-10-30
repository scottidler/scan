# Design Document: Shakedown Fixes After v0.5.7, Palette, and Pane Zoom

**Author:** Scott Idler
**Date:** 2026-10-29
**Status:** Implemented
**Review Passes Completed:** 5/5

## Summary

A tui-test shakedown of the installed v0.5.7 across 15 targets found 22 defects, and Scott raised four more items from his own screenshots: traceroute rows that read `timeout` under `traced`, a DNS TTL stuck at `0s`, red text that is hard to read, and a request to zoom one pane with Enter. This doc fixes all of them. The zoom work rides on one generic scroll mechanism that also fixes the panes that clip today with no marker.

## Problem Statement

### Background
- v0.5.7 shipped `docs/design/2026-10-29-shakedown-v0.5.6-fixes.md`.
- Scott asked "time to go back to the tui testing tools ... see what else we can fix?", sent two screenshots (`www.tatari.tv`, `be.tatari.tv`), said "the red text in this font or in this terminal is hard to read", and proposed Enter to zoom a pane and Esc to go back.
- Evidence: shakedown captures, logs and cell dumps from this session. Anchors are `path:line` at `ae9a394` (v0.5.7).

### Problem

| # | Defect | Root cause | Evidence | Raised by |
|---|---|---|---|---|
| A | Traceroute shows `* (timeout)` rows under `Status: traced`; the destination and Duration fall below the pane | one row per hop from hop 1 (`src/tui/traceroute.rs:98-130`); silent hop labelled `timeout` (`:114-116`); hop numbers ≥11 red (`:119-125`) | Scott's screenshot; at 80x24 only hops 1-5 of 11 show | Scott |
| B | DNS `TTL: 0s` for most of each minute | `ttl_remaining()` counts down from query time (`src/scan/dns.rs:31-34`); fixed 60s re-query (`:219`); systemd-resolved returns the remaining cached TTL (`dig` 14 vs authoritative 60) | watch run: 0, 59, 28, 0, 0, 58 at 30s steps | Scott |
| C | Red text hard to read | 89 `Color::Red` (ANSI 1) outside tests, 0 `LightRed`; red also marks non-errors (hop ≥11, TTL ≤60s, `Privacy: Open`, 500ms+ HTTP time, EPP locks, MX priority >20, >5 open ports); Magenta and Blue body text has the same contrast risk | `tui-test cells`: every red span fg 1 | Scott |
| D | No way to see a pane's full data | panes are fixed grid cells; no zoom; Enter unhandled (`src/tui/mod.rs:160-199`) | n/a | Scott |
| 1 | No AAAA: Connectivity red `IPv6 no ping reply`; status `ipv4 only` in yellow | `PingStatus::was_attempted()` is true for `NoAddress` (`src/scan/ping.rs:68-70`), so `connectivity.rs:313-327` records failures, the family turns Disconnected (`:250`), falls back to `"no ping reply"` (`:39`) in red (`:138`); status matrix `:403`, `:420-422` | `be-200`, `tatari-200`; mirror case `v6-200` shows `IPv4 no ping reply` | Scott (screenshot), shakedown |
| 2 | `scale 0-1ms` with zero successful samples | title printed when any sample exists (`connectivity.rs:547`); `scale_max_us` falls back to 1ms (`src/tui/sparkline.rs:69-76`) | `be-200` | Scott (screenshot) |
| 3 | After `p`, panes keep the other protocol's data | scanners keep `result` across a protocol change (`src/scanner.rs:137-157`, `:219-235`); Connectivity records no sample or state for `NotQueried` (`connectivity.rs:324-325`, `:349`); geoip, port, tls build their own aggregate (`src/scan/geoip.rs:772-775` `{:?}`, `src/scan/port.rs:703-707`, `src/scan/tls.rs:1177-1181`) | `ix-51-p2`: red `failed:` over stale `IPv4 Route: ✓ reached`; GeoIP `IPv4=NotQueried` | shakedown |
| 4 | DMARC `missing` for every domain that publishes it at `_dmarc.` (the standard place); DKIM detection invented | DMARC searched only in apex TXT (`src/scan/dns.rs:240-249`; an apex `v=DMARC1` would match, which no checked domain has); any apex TXT with `p=` adds `default._domainkey` (`:255-267`) | `dig _dmarc.google.com` returns `v=DMARC1`; pane says `missing` | shakedown |
| 5 | No IPv6 route: Ports `Closed: 6` | every connect error is `Ok(None)` (`src/scan/port.rs:355`), counted closed (`:277`) | `v6-200` | shakedown |
| 6 | CNAME and CAA never shown | no CNAME/CAA query in `perform_dns_lookup` (`src/scan/dns.rs:288-790`); TUI sections exist (`src/tui/dns.rs:207`, `:303`) | `dig` shows `www.tatari.tv` CNAME and 4 CAA | shakedown |
| 7 | PTR queried, never shown; IP target DNS pane is empty | no PTR section in `build_dns_result_lines` (`src/tui/dns.rs:129-443`) | `one-200`; log `ptr_status=Success(1)` | shakedown |
| 8 | Ports `↻ refreshing` shows `Progress: 99% (6/6)` | progress computed from the previous complete result, capped at 99 (`src/tui/ports.rs:102-130`, `:16`) | every capture | shakedown |
| 9 | Failure reason vanishes on the next cycle | `status_label` ignores `error` while `Running` (`src/tui/status.rs:17-20`); `mark_running` keeps it (`src/scanner.rs:141`) | `neverssl-200`, `dead-200` | shakedown |
| 10 | Traceroute scroll counts 4 lines never drawn | `calculate_content_lines` adds `+3 +1` (`src/tui/traceroute.rs:233-236`) | `sc2.log` `actual_lines=19` vs 15 drawn | shakedown |
| 11 | Cert CN cut at 25 chars, no `…` | `common_name_display` (`src/tui/security.rs:854`, const `:19`) | github `Issuer: Sectigo Public Server Aut` | shakedown |
| 12 | Only Security, DNS, Traceroute scroll; others clip silently | three hand-copied scroll impls (`src/tui/dns.rs:35-85`, `src/tui/security.rs:29-80`, `ScrollablePane` only on traceroute `:213`); key routing by id and downcast with hardcoded `pane_areas[2][2]` (`src/tui/layout.rs:361-446`, `:399-401`) | `tatari-80` WHOIS cut after Registrar | shakedown |
| 13 | `PFS: no` after a failed handshake | drawn without checking `connection_successful` (`src/tui/security.rs:341-345`) | `selfsigned-200` | shakedown |
| 14 | `Grade: APlus` and other enum names in panes | `{:?}` in pane text: `src/tui/security.rs:247` (grade), `:561` (CSP), `:603` (CORS), `src/tui/whois.rs:205` (privacy) | `sc2-30-sec-down60` | shakedown |
| 15 | GeoIP `located` for loopback and private addresses | no local classification; ipinfo `"bogon": true` ignored (`src/scan/geoip.rs:448-494`) | `localhost-200`, `dead-200` | shakedown |
| 16 | Unreachable target gets TLS `Grade: F` | connect failure returns early with `Ok` and `connection_successful=false` (`src/scan/tls.rs:958-971`), carrying `TlsData::new`'s default `security_grade: F` (`:182`) | `v6-200`, `dead-200` | shakedown |
| 17 | EPP `client*Prohibited` locks red | any status without `ok`/`pending` is red (`src/tui/whois.rs:176-183`) | `be-colors` fg 1 | shakedown |
| 18 | `--no-tui` and TUI disagree on silent hops | `pretty.rs:291-295` counts `packet_loss > 0.5`; TUI counts no-reply hops (`src/tui/traceroute.rs:102`) | `notui-tatari-last` `8 timeouts` vs 7 in TUI | shakedown |
| 19 | Stray glyph after `⏱️` | 16 VS16 emoji sequences in TUI code; ratatui measures 2 cells, the emulator draws 1 (`src/tui/http.rs:93,129,205,246,251`, `src/tui/ports.rs:219,260`, `src/tui/traceroute.rs:65,77,143,168`, `src/tui/security.rs:338,433,654`, `src/tui/whois.rs:213`, `src/tui/geoip.rs:131`) | `neverssl-200` `⏱️P  Time`; cell dump | shakedown |
| 20 | Null MX `. (pri: 0)` shown as a mail server | `src/tui/dns.rs:351-370` | `example-200` | shakedown |
| 21 | Compact Connectivity `v6 ---` vs full-size red label | `latest_text` (`connectivity.rs:567`) vs `family_failure_label` (`:539`) | `tatari-80` vs `tatari-200` | shakedown |
| 22 | `First TUI render completed` logged at quit | logged after `app.run` returns (`src/main.rs:174-178`) | `ix.log` `startup_to_render=148939ms` | shakedown |
| 23 | `OCSP: no` always shown | OCSP stapling never set outside tests (`src/scan/tls.rs:153,180`) | every Security capture | research |

### Goals
- Every label tells the truth: no failure color for a family that has no address, no grade without a handshake, no stale data under a failure, no enum names, no fake progress.
- DNS shows the records that exist: CNAME, CAA, PTR, null MX named as such. The Security pane's DMARC line reads `_dmarc.`. A TTL never shows a bare `0s`: expiry triggers a re-query, and an expired TTL reads `expired, refreshing`.
- Red means a fault, and reads clearly on a dark terminal.
- Every pane scrolls, marks overflow, and can be zoomed full-screen with Enter for its full data.
- The traceroute route fits its pane at 80x24.

### Non-Goals
- Excluded: `pretty.rs` (`--no-tui`) colors. It uses the `colored` crate; the palette is TUI-only.
- Excluded: making existing network-hitting tests hermetic (carried from prior docs).
- Parked, revisit when zoom has shipped and a pane's detail view is found thin: new collection of raw HTTP response headers and the `Server:` value, closed and filtered port number lists, the TLS supported-cipher list, and OCSP stapling. Zoom shows only data the scanners collect today, plus items 4, 6, 7.
- Excluded: mouse support. Mouse capture stays as is.

## Proposed Solution

### Overview
Fix forward at the cited seams. Four pieces of shared code each kill a class:
- `src/tui/theme.rs`: semantic colors; no `Color::` literal outside it.
- Layout-owned scroll: one mechanism for every pane, used by zoom.
- One protocol-change reset in `Scanner::run`.
- `family_failure_summary` for every per-family scanner aggregate.

### Architecture

- **Theme (C, 17):**
  - `src/tui/theme.rs` holds semantic constants, copying the shape of `~/repos/scottidler/loopr/v4/src/tui/app.rs` (`pub mod colors`): `BAD` = `LightRed`, `WARN` = `Yellow`, `GOOD` = `Green`, `VALUE` = `Cyan`, `LABEL` = `White`, `MUTED` = `Gray`, `ACCENT` (replaces Magenta and Blue body text), and focused/unfocused border colors (`src/tui/pane.rs:53-57`).
  - Reclassify non-faults: hop number neutral; TTL ≤60s `WARN`; MX priority neutral; `Privacy: Open` `VALUE`; EPP locks `GOOD`; HTTP time ≥500ms `WARN`; HTTP 5xx `BAD`; >5 open ports `WARN`.
  - Test: a unit test reads every `src/tui/*.rs` source and fails on any `Color::` outside `theme.rs` and `#[cfg(test)]` modules. A test, not a doc rule, so the class cannot come back.
  - `create_block` (`src/tui/pane.rs:53-57`) takes its border colors from the theme too.
- **Glyphs (19):** replace each VS16 emoji with an `Emoji_Presentation=Yes` codepoint that is 2 cells everywhere (`⏱️`→`⏳`, `⚠️`→`❗`, `🗺️`→`🧭`, `🛡️`→`🔰`, `🏛️`→`🏦`, `🖥️`→`💻`). Test: no rendered pane contains U+FE0F.
- **Honest labels (2, 8, 11, 13, 14, 18, 20, 21, 22, 23):**
  - Sparkline title prints `scale 0-N` only when a successful sample is visible; `← Ns` stays.
  - Ports refresh: delete the fake progress; the header already says `↻ refreshing`.
  - Cert CN: remove the 25-char cap; `fit_line` adds `…`.
  - Security Features: `PFS: n/a` and `OCSP: not checked` in `MUTED` when there was no handshake; `OCSP: not checked` always, since it is never collected.
  - No `{:?}` in pane text: user-facing labels for `SecurityGrade` (`as_str`, `src/scan/http.rs:1066`), CSP strength, CORS level, privacy.
  - `TracerouteData::silent_hops()` used by both the TUI and `pretty.rs`; a silent hop is one where no probe answered.
  - A single `0 .` MX record renders `MX: none (null MX)`.
  - One family-state text function for Connectivity, with a short form for compact mode.
  - Log `First TUI render completed` inside `TuiApp::run` after the first `terminal.draw`.
- **Failure honesty in scanners (3c, 5, 9, 15, 16):**
  - `status_label`: `Running` with `error` set reads `failed: <e> · ↻ retrying`.
  - Ports: classify the connect error. ECONNREFUSED is closed; `classify_route_error` `NoRoute` fails the family (`no IPv6 route on this host`); EHOSTUNREACH and others count as filtered.
  - TLS: a connect or handshake I/O error returns `Err`, classified by `classify_route_error`. Certificate rejection keeps the `Rejected` path and its F.
  - GeoIP: classify locally before any request (loopback, private, link-local, documentation, CGNAT 100.64/10, unique-local, IPv6 2001:db8::/32; the last two by hand since `is_shared` and `Ipv6Addr::is_documentation` are unstable). Result: a new `NotGeolocatable(kind)` status (`src/scan/geoip.rs:50` has only Success/Failed/NoAddress/NotQueried), rendered `not geolocatable (<kind> address)` in `MUTED`, zero requests. Also honor ipinfo `bogon`.
  - geoip, port, tls aggregates go through `family_failure_summary` (`src/scan/mod.rs:110`).
- **Protocol and no-address state (1, 3a, 3b):**
  - Connectivity gets a `NoAddress` family state, fed directly from `PingStatus::NoAddress`, not through `was_attempted`. Label `no IPv6 address` (or IPv4) in `MUTED`.
  - Status matrix: `(Connected, NoAddress)` reads `ipv4` in `GOOD`; `NoAddress` never makes the status a warning.
  - `Scanner::run` keeps the protocol of its last scan. At the start of each scan, whichever `select!` branch woke the loop, a protocol different from the last one clears that scanner's `result`, `error` and `history`. Detecting it in the protocol-change branches (`src/scanner.rs:64-76`, `:97-104`) is not enough: when the tick and the change are both ready and the tick wins, `borrow_and_update()` (`:81`) takes the new protocol and neither branch runs. Only protocol-following scanners (`uses_protocol()`) reset; WHOIS keeps its data. The retained-result-on-refresh rule from v0.5.6 is unchanged for ordinary refreshes.
  - Connectivity sample ingestion moves out of `ConnectivityPane::render` (today `connectivity.rs:463` -> `update_sparklines`, deduped by `queried_at` at `:280-300`) into a per-tick `TuiApp` step that runs whether or not the pane is drawn. Zoom on another pane then loses no ping cycles.
  - That ingestion step remembers the protocol it last saw. On a change it clears the disabled family's samples and the pane shows `disabled (p)` in `MUTED`. This is the display-side half of the same reset; the scanner clears its own state, Connectivity clears its sparkline buffer.
  - Selecting a family the target has no address for reads `MUTED` `no IPv6 address`, never red `failed`.
- **DNS collection and cadence (4, 6, 7, B):**
  - Extract the PSL lookup from `WhoisScanner::registrable_domain` (`src/scan/whois.rs:215`) and its cache into `src/scan/psl.rs`, used by WHOIS and DNS. Same cache file, same rules.
  - DMARC: query TXT at `_dmarc.<host>`, then `_dmarc.<registrable domain>` (RFC 7489 organizational fallback). The result fills the existing `EmailSecurityAnalysis::dmarc_record` (`src/scan/dns.rs:76-78`, `:271`), which the Security pane already reads (`src/tui/security.rs:264`, `:699-705`); no second field. If the suffix list is unavailable, only `_dmarc.<host>` is queried. The debug log records which name answered.
  - DKIM: delete the invented `default._domainkey` detection. Without a selector there is nothing to query, so the Security pane shows `DKIM: not checked (needs selector)`.
  - CNAME and CAA: explicit `resolver.lookup(name, RecordType::CNAME | CAA)`, like the SOA lookup (`src/scan/dns.rs:577-578`), with `CNAME_status` and `CAA_status` fields.
  - PTR: a `PTR:` section; for an IP target it leads the pane.
  - TTL cadence: a `Scanner::next_delay(&self, result) -> Option<Duration>` hook, default `None` (use `interval()`). DNS returns the time to the earliest per-record expiry (`queried_at + ttl`), clamped to 10s..60s, or `None` when there are no records (NXDOMAIN, failure). The loop computes it before `record_outcome` consumes the result, then calls `ticker.reset_after(d)` (tokio 1.48 `Interval::reset_after`); `None` leaves the ticker untouched. The debug log records the chosen delay.
  - TTL display: `<n>s (cached)`, since the stub resolver's TTL is not authoritative. At 0 it reads `expired, refreshing` in `MUTED` until the re-query lands, which covers stub TTLs under the 10s floor and failed refreshes.
- **Generic scroll and overflow (10, 12):**
  - `Pane` gains `fn content(&self, state: &AppState, width: u16, detail: Detail) -> Vec<Line<'static>>` with `Detail::{Normal, Zoomed}`. The default returns Normal content for both.
  - Row contract: `content()` returns rows already laid out to `width`, one `Line` per screen row. Lines that wrap today (`fit_lines_except` in `src/tui/whois.rs:281`, `src/tui/geoip.rs:191`, HTTP failure lines) are wrapped into several `Line`s by a shared `wrap_line(line, width) -> Vec<Line>` in `src/tui/text.rs`. The renderer never wraps, so `content().len()` is the row count the scroll clamp and `↓ N more` use.
  - Normal detail fits identifier lines with `fit_line`; Zoomed detail wraps them with `wrap_line`, so zoom shows full TXT records, URLs and certificate names.
  - `PaneLayout` owns scroll offsets keyed by `(pane id, Detail)`, takes the visible height from the rect it draws, and clamps against `content().len()` on every render, so a resize or shrinking content re-clamps. One function computes pane rects for both render and key handling, which removes the `pane_areas[2][2]` hardcode and the `terminal.size()` rebuild in `mod.rs:186-188`.
  - Overflow marker: when content is longer than the rect, the bottom border shows `↓ N more` (and `↑ N` when scrolled).
  - The three bespoke scroll impls, `ScrollablePane`, and `calculate_content_lines` are deleted.
  - Connectivity keeps a custom render because it draws sparklines; it does not scroll and is exempt from the scroll tests by name. `Pane` gains `fn render_detail(&self, frame, area, state, focused, detail: Detail)` defaulting to `render`; only Connectivity overrides it.
- **Traceroute layout (A):**
  - The pane is about 24 columns inside at 80x24 (`TRACEROUTE_PANE_WIDTH_PERCENT` = 33, `src/tui/layout.rs:30`), so the destination gets its own row:
    - `📍 IPv4 ✓ reached` (a silent target keeps `✗ target silent (last reply: hop N)`)
    - `→ 216.150.16.193 (3ms)` (about 22 cells)
  - Runs of silent hops collapse to one row: `3-9: no reply (7 hops)`. A single silent hop reads `3: no reply`.
  - The word `timeout` is gone from hop rows. Hop numbers use `LABEL`.
  - Duration stays the last row of the pane. Zoom repeats it.
- **Zoom (D):**
  - `PaneLayout.zoomed: bool`. Enter zooms the focused pane to the full frame and renders `content(Detail::Zoomed)`, scrolled by the same layout-owned offsets (a separate offset per pane for zoom, reset on entering it). Esc leaves zoom.
  - Zoomed Connectivity overrides render (taller graphs, loss, jitter) and does not scroll.
  - A resize while zoomed stays zoomed and re-clamps the scroll offset.
  - Esc when not zoomed keeps today's behavior (quit). `q` and Ctrl-C are unchanged.
  - While zoomed, Left/Right (and Tab/BackTab) move the zoom to the previous/next pane, and that pane's zoom offset resets to 0; Up/Down/j/k/Home scroll.
  - Detail per pane, from data already collected:
    - Traceroute: every hop, every probe's IP and RTT, per-hop loss, both families, Duration.
    - DNS: every record with its own TTL, full TXT, all SOA fields, PTR.
    - Security also lists the email-security records (SPF, DMARC with its full text).
    - HTTP: full redirect chain, security headers, CSP, CORS, caching, vulnerabilities.
    - Security: full certificate chain (subject, issuer, serial, validity, signature algorithm, key, SANs), supported versions, vulnerabilities.
    - WHOIS: every field, including contacts, DNSSEC, last updated.
    - Ports: every open port with service, version and banner.
    - GeoIP: every field.
    - Target: unchanged content, full width.
    - Connectivity: a taller sparkline per family, plus loss % and jitter computed from its 200-sample history. These are new numbers, not new collection; they are only correct because ingestion no longer depends on the pane being drawn.
  - The footer shows the active keys: `Esc back · ←/→ pane · ↑/↓ scroll`.

### Data Model
- `theme.rs`: `pub const` colors as above.
- `enum Detail { Normal, Zoomed }`.
- `PaneLayout`: `scroll: HashMap<(&'static str, Detail), u16>`, `zoomed: bool`.
- Connectivity family state: add `NoAddress` and `Disabled`.
- `DnsResult`: add `CNAME`, `CNAME_status`, `CAA`, `CAA_status`. DMARC reuses `EmailSecurityAnalysis::dmarc_record`. Delete the invented DKIM entries.
- `GeoipStatus`: add `NotGeolocatable(AddressKind)`.
- `Scanner::run`: `last_protocol: Option<Protocol>` local to the loop.
- `Scanner` trait: `fn next_delay(&self, result: &ScanResult) -> Option<Duration> { None }`.
- `src/scan/psl.rs`: `registrable_domain(host, deadline) -> eyre::Result<Option<String>>`, moved from `WhoisScanner`.

### API Design
```rust
// tui/pane.rs
fn content(&self, state: &AppState, width: u16, detail: Detail) -> Vec<Line<'static>>;
fn render_detail(&self, frame: &mut Frame, area: Rect, state: &AppState, focused: bool, detail: Detail);
// tui/text.rs
pub fn wrap_line(line: Line<'_>, width: u16) -> Vec<Line<'static>>;
// scanner.rs (Scanner trait)
fn next_delay(&self, result: &ScanResult) -> Option<Duration> { None }
// scan/traceroute.rs
impl TracerouteData { pub fn silent_hops(&self) -> usize; }
// scan/psl.rs
pub async fn registrable_domain(&self, host: &str, deadline: Instant) -> eyre::Result<Option<String>>;
```

### Implementation Plan

Each phase: one commit, `otto ci` green, each new test shown failing with its fix undone.

#### Phase 0: Prove the replacement glyphs are 2 cells in Scott's terminal
**Model:** sonnet (operator step, zero code)
- Scott runs this in his terminal and sends a screenshot:
  ```
  printf 'xx|\n⏳|\n❗|\n🧭|\n🔰|\n🏦|\n💻|\n'
  ```
- **Success criteria:** every glyph row's `|` lines up with the `xx|` ruler row. Any glyph whose `|` does not line up is dropped from the replacement set; if all fail, Phase 2 drops the emoji instead.

#### Phase 1: Honest small labels
**Model:** sonnet
- Items 2, 8, 11, 13, 14, 18, 20, 21, 22, 23.
- **Success criteria:**
  - `render_pane` of Connectivity with only failed samples contains no `scale 0-`; full and compact modes render the same family-state text for a NoRoute fixture (21).
  - Security renders `Grade: A+` (not `APlus`), user labels for CSP strength and CORS level, `OCSP: not checked`, and `PFS: n/a` for a failed handshake (13); WHOIS renders a privacy label, not the enum name. A 40-char CN fixture renders in full at 200x55 (11).
  - The TUI and `pretty.rs` report the same silent-hop count for one fixture (18); a refreshing Ports render contains no `Progress:` (8); an MX fixture `0 .` renders `MX: none (null MX)` (20); a log-capture test sees `First TUI render completed` before any key is read (22).

#### Phase 2: Theme and glyphs
**Model:** sonnet
- Item C, 17, 19: `theme.rs`, migrate every color site per the reclassification, replace the VS16 glyphs, add the lint rule.
- **Success criteria:**
  - The no-`Color::`-outside-`theme.rs` unit test passes, and fails when one `Color::Red` is added back to a pane.
  - No rendered pane contains U+FE0F.
  - `client transfer prohibited` renders in `GOOD`; a failed ping label renders in `LightRed`.

#### Phase 3: Failure honesty in scanners
**Model:** opus
- Items 9, 3c, 5, 15, 16.
- **Success criteria:**
  - `status_label` for `Running` with `error` set contains `failed:`.
  - A fake connect returning ENETUNREACH fails the Ports family and never counts a closed port; the same input makes TLS an `Err`, never a graded result.
  - GeoIP for 127.0.0.1, 10.0.0.1 and 192.0.2.1 makes zero requests to a fake ipinfo server and reports `not geolocatable`.

#### Phase 4: Protocol and no-address state
**Model:** opus
- Items 1, 3a, 3b; protocol reset at scan start; Connectivity ingestion moved out of render (must land before Phase 8).
- **Success criteria:**
  - Five cycles of IPv6 `NoAddress` render `no IPv6 address` in `MUTED` and an overall status of `ipv4`, never `no ping reply` or `ipv4 only`.
  - After a protocol change, a protocol-following scanner's state has `result == None` until its next scan, including the both-ready case where the tick branch wins (a test drives both futures ready); WHOIS keeps its result.
  - Connectivity's disabled family draws no bars; N ping results published while the pane is not rendered yield N samples.

#### Phase 5: DNS collection and TTL cadence
**Model:** opus
- Items 4, 6, 7, B; `src/scan/psl.rs` extraction.
- **Success criteria:**
  - Unit: the email-security analysis fills `dmarc_record` from a `_dmarc.` TXT answer and leaves apex-only TXT without DMARC; a DNS fixture with CNAME and CAA renders both sections; an IP-target fixture renders `PTR:` first. Live coverage is AC5.
  - Unit: `next_delay` for records expiring in 4s, 30s and 300s returns 10s, 30s and 60s (injected `now`); none returns `None`. A TTL at 0 renders `expired, refreshing`.
  - With tokio paused time, a stub scanner whose `next_delay` returns 2s scans again within 2s, not 60s (timer plumbing only).

#### Phase 6: Generic content, scroll and overflow
**Model:** opus
- Items 10, 12: `Pane::content`, layout-owned scroll, one rect function, overflow marker; delete the bespoke impls.
- **Success criteria:**
  - Every pane except Connectivity whose content exceeds its rect shows `↓ N more` (one parametrized test), with N equal to the rows not shown, including a WHOIS fixture whose wrapped lines take several rows.
  - Scrolling to the end reveals the last built line in every pane except Connectivity; a resize or content shrink re-clamps the offset.
  - Up after scrolling to the end changes the view on the first press (item 10).

#### Phase 7: Traceroute layout
**Model:** sonnet
- Item A.
- **Success criteria:**
  - In the full 80x24 dashboard (`dashboard_pane_size`), the tatari fixture shows `→ 216.150.16.193 (3ms)`, `3-9: no reply (7 hops)` and the Duration row.
  - No hop row contains `timeout`; hop numbers are not `BAD`.

#### Phase 8: Zoom
**Model:** opus
- Item D.
- **Success criteria:**
  - A layout render with zoom on shows exactly one pane title; Right while zoomed shows the next pane's title at scroll offset 0; a resize while zoomed stays zoomed.
  - Esc while zoomed leaves zoom and does not quit; Esc while not zoomed quits. The zoom and grid scroll offsets of one pane are independent.
  - Traceroute zoomed content shows every probe RTT for a fixture hop; DNS zoomed content shows a 300-char TXT record in full (wrapped).

## Acceptance Criteria

Live checks run the installed binary: `tui-test run --session ac --cols 200 --rows 55 -- scan <target>`, wait with `tui-test --session ac expect text "zz-never" --timeout 55000` (exit 1 expected, a wait only), run the checks, then `tui-test close --all`.

All observed lines: installed `scan v0.5.7` (main ae9a394), run by `zsh` with a `tt()` wrapper function, 2026-10-29.

- [ ] **AC1** `www.tatari.tv`: `expect text "IPv6 no ping reply" --not` exits 0, and `expect text "no IPv6 address"` exits 0.
  - Observed on main: 1, 1.
- [ ] **AC2** `2606:4700:4700::1111`, on a host with no IPv6 route (true of desk today; this criterion depends on that): `expect text "Closed: 6" --not` exits 0, `expect text "Grade: F" --not` exits 0, `expect text "one.one.one.one"` exits 0.
  - Observed on main: 1, 1, 1.
- [ ] **AC3** `www.tatari.tv` at `--cols 80 --rows 24`: `expect text "(timeout)" --not` exits 0, and `expect text "216\.150\.\d+\.\d+ \(\d+ms" --regex` exits 0 (the destination in the route header).
  - Observed on main: 1, 1.
- [ ] **AC4** `www.tatari.tv`: `key press shift+tab` (Security -> Traceroute; amended from `BackTab`, which tui-test types as the literal text "BackTab": under `cat -v`, `expect text "BackTab"` exits 0 and `shift+tab` shows `^[[Z`), `key press Enter`, then `expect text "┌SECURITY" --not` exits 0 and `expect text "┌TRACEROUTE"` exits 0; then `key press Escape` and `expect text "┌SECURITY"` exits 0.
  - Observed on main: 1, 0, 1. The middle check passes on main because every pane is always drawn; it is meaningful only paired with the first. Escape quits on main, so the third fails.
- [ ] **AC5** `google.com`: `key press Enter` (Security has focus at start), then `expect text "DMARC: configured"` exits 0.
  - Observed on main: 1.
- [ ] **AC6** `www.tatari.tv`: `expect text "client transfer prohibited" --fg 1` exits 1 and `expect text "client transfer prohibited" --fg 2` exits 0; on `192.0.2.1`, `expect text "no echo reply" --fg 9` exits 0.
  - Observed on main: 0, 1, 1. Control on main: `expect text "no echo reply" --fg 1` exits 0 and `expect text "client transfer prohibited"` (no color) exits 0, so `--fg <index>` matches as intended and the text is present.

## Resolved Decisions
- 2026-10-29: Esc leaves zoom; when not zoomed Esc keeps quitting. Changing an existing quit key was not requested.
- 2026-10-29: Left/Right in zoom move to the next pane, so zoom works as a full-screen pager over all panes.
- 2026-10-29: the PSL lookup moves to `src/scan/psl.rs` for DNS and WHOIS. The v0.5.6 ruling keeps scanners independent; a shared module, not a cross-scanner call, respects it.
- 2026-10-29: TTL re-query floor 10s, ceiling 60s; TTLs labelled `(cached)`.
- 2026-10-29: no-AAAA target reads `ipv4` in `GOOD`; the missing family is `MUTED`, never a warning.
- 2026-10-29: palette is TUI-only.
- 2026-10-29: new data collection for zoom (raw headers, port lists, cipher list, OCSP) is parked; OCSP gets an honest `not checked` now.
- 2026-10-29: `BAD` = `LightRed` (ANSI 9), not a fixed RGB, so the terminal theme still controls the shade.
- 2026-10-29, panel round 1 (Gemini + Codex): 4 must-fix and 8 cheap-win folded in:
  - Connectivity ingestion moves out of render (zoom would starve it); the traceroute destination gets its own row (the header could not fit 24 columns); the protocol reset is detected at scan start (both-ready race); `content()` returns laid-out rows with a shared `wrap_line`.
  - TTL goal restated with `expired, refreshing`; DMARC reuses `dmarc_record`; Duration stays in the traceroute pane; Connectivity exempt from scroll tests by name; zoom offset resets on Left/Right; Phase 0 per-glyph ruler; Phase 8 criteria widened; AC6 gets a positive color check.
  - Also folded: item 16's root cause corrected to `TlsData::new`'s default F; item 4 worded precisely; `NotGeolocatable` status named; new-lookup timeout risk row; delay and DMARC-source debug logs.
  - Synthesis: `~/.cache/review-panel/runs/AEaDBvUI/synthesis.md`.
- 2026-10-29: rejected architect's "clearing on `p` destroys data". Item 3 is that old-protocol data under a new-protocol failure is wrong, and the Goals forbid stale data; the panel agreed. The two resets (scanner state, Connectivity buffer) are named as halves of one event.
- 2026-10-29: kept Connectivity loss and jitter in zoom against staff's unrequested-scope note. Scott asked for zoom "possibly with more detail"; both numbers come from data already held, and the ingestion fix makes them correct.

## Alternatives Considered

### Fixed RGB palette
- **Pros:** exact contrast everywhere.
- **Cons:** ignores the terminal theme; clashes on light backgrounds.
- **Why not chosen:** bright ANSI fixes the contrast and keeps the user's theme.

### Zoom without generic scroll
- **Pros:** smaller change.
- **Cons:** a zoomed pane taller than the screen still clips; three scroll impls stay.
- **Why not chosen:** one mechanism serves both, and it kills finding 12 and 10.

### TTL label `expired` instead of re-query
- **Pros:** no scanner-loop change.
- **Cons:** DNS shows stale answers for most of each minute.
- **Why not chosen:** TTL means "re-ask now"; the hook is small and default-off for other scanners.

### Drop emoji entirely
- **Pros:** no width risk.
- **Cons:** loses the scan-at-a-glance icons Scott's layout uses.
- **Why not chosen:** fallback only if Phase 0 fails.

## Technical Considerations

### Dependencies
- None new. hickory `RecordType::CNAME/CAA`, std IP methods, tokio `Interval::reset_after` are all available.

### Testing Strategy
- `render_pane` tests per pane; local fakes for ipinfo and DNS where possible; tokio paused time for the cadence hook.
- Live acceptance criteria after release.

### Rollout Plan
- Single repo, ungated. Release through `bump release` after the implementation audit.

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Replacement glyphs are 1 cell in Scott's terminal | Low | Med | Phase 0 checks before Phase 2; fallback drops emoji |
| Generic scroll changes pane geometry and breaks pane tests | Med | Low | Phase 6 runs every pane through one parametrized test |
| TTL re-query hammers a resolver with tiny TTLs | Low | Low | 10s floor |
| Clearing results on protocol change blanks panes briefly | High | Low | expected: the old protocol's data is wrong for the new one |
| Esc pressed twice (leave zoom, then quit) exits by accident | Med | Low | zoom footer names `Esc back`; `q` stays the documented quit key |
| `ENETUNREACH` vs `EHOSTUNREACH` split differs on macOS | Low | Low | classification goes through `classify_route_error`, which already reads errno and text |
| New DNS lookups (CNAME, CAA, `_dmarc.`, PSL) push a slow resolver past the 30s DNS deadline, which discards the whole result (pre-existing behavior) | Low | Med | each new lookup is wrapped in its own timeout like A/AAAA; the deadline itself is unchanged |

## Open Questions

None.

## Review Pass Log

- Pass 1 (draft): problem table from the shakedown and the research brief; 9 phases.
- Pass 2 (correctness): DMARC renders in the Security pane, not DNS (`src/tui/security.rs:699-705`); Goals and the zoom list corrected. Verified `Pane::render` is `&self` and Enter is unhandled (`src/tui/mod.rs:160-199`), Esc quits (`:162`).
- Pass 3 (clarity): the theme rule is a unit test, not a doc rule; Phase 1 and 2 criteria name exact strings instead of "no enum names".
- Pass 4 (edge cases): TTL hook returns `None` with no records and resets only on success; DMARC without a suffix list queries the host only; zoom keeps its own scroll offset and survives resize; double-Esc and macOS errno rows added to Risks.
- Pass 5 (excellence): every acceptance criterion run against installed v0.5.7, observed output recorded; all fail there as they should.
- Panel round 1: see Resolved Decisions. AC6's new `--fg 2` check run on v0.5.7 and recorded.

## References
- `docs/design/2026-10-29-shakedown-v0.5.6-fixes.md`
- `~/repos/scottidler/loopr/v4/src/tui/app.rs` (palette precedent)
- RFC 7489 (DMARC organizational domain), RFC 7505 (null MX)
