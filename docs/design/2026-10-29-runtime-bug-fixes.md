# Design Document: Runtime Bug Fixes Found by tui-test

**Author:** Scott Idler
**Date:** 2026-10-29
**Status:** Implemented
**Review Passes Completed:** 5/5

## Summary

The live TUI was driven with `tui-test` (headless PTY + terminal emulator) against google.com, 1.1.1.1, a GitHub URL, expired.badssl.com and a nonexistent domain. Fourteen defects came out of it. Ping never works, TLS cert analysis never works, every rescan blanks its pane, `p` only relabels, and HTTP measures the wrong thing. This doc fixes all fourteen and adds the missing test layer (ratatui `TestBackend` pane renders over fake `AppState`) so each one has a regression test that bites.

## Problem Statement

### Background

- `scan` is meant to be a btop-style live dashboard for one target (URL, domain, or IP): 8 concurrent scanners feed 9 panes, redrawn every 250ms.
- `docs/ipv4-ipv6-first-class-support.md` makes IPv4/IPv6 first class and says protocol switching must be "intuitive and responsive".
- Test coverage today: 181 inline unit tests, no pane render tests, no `tests/` dir, no `[dev-dependencies]`. Nothing exercises what the user sees.
- Code anchors below are `path:line` at `23f3a43`.

### Problem

Each item is a confirmed root cause, with the evidence that surfaced it.

| # | Defect | Root cause | Evidence |
|---|---|---|---|
| 1 | Ping always fails | `PingScanner` build-args passes the timeout in ms to `ping -W` (`src/scan/ping.rs:353-356`); iputils reads seconds. No OS handling | log: 830 lines of `ping: bad linger time: 5000`; `ping -W 5000` exits 2, `-W 5` exits 0 |
| 2 | Ping failure is invisible | `scan()` returns `Err` when all protocols fail (`ping.rs:243-256`), discarding per-protocol `Failed`; connectivity pane reads only `.result`, never `.error` (`src/tui/connectivity.rs:338-343`) | pane shows `Status: checking connectivity` forever |
| 3 | Every rescan blanks its pane | `Scanner::run` inserts a fresh `ScanState { result: None, history: [] }` each cycle (`src/scanner.rs:54-63`); copied from `docs/architecture.md:107-116` | ports pane drops to `scanning... / detecting...` every 30s; target count 7/8 -> 6/8 |
| 4 | `p` only changes the label | `protocol` is a by-value arg to `Scanner::run` (`scanner.rs:29`), set once by `spawn_scanner_tasks` (`src/scan/mod.rs:46-85`); key handler mutates `AppState.protocol` and stops at a TODO (`src/tui/mod.rs:143-157`) | after `p` -> IPv4, log still pings `2607:f8b0:...` with `protocol=IPv4+IPv6` |
| 5 | HTTP measures the IP, not the site | URL targets `set_host(ip)` (`src/scan/http.rs:142-147`); so HTTPS by IP fails cert validation unless the cert carries an IP SAN, and the URL target errors outright. Domain and IP targets try `https://{ip}` then fall back to `http://{ip}` silently (`:148-151`). IPv6 is unbracketed (`invalid port number`) | google.com shows `http://142.251.45.142/` and Grade C; GitHub URL target shows HTTP ❌; `curl https://<google ip>/` -> 000 |
| 6 | Cert analysis always fails | expiry parsed from `Asn1Time::to_string()` expecting `YYMMDDHHMMSSZ` (`src/scan/tls.rs:619-655`); openssl prints `Sep 28 18:38:33 2026 GMT` | log: `Unsupported ASN1 time format: Sep 28 18:38:33 2026 GMT` for google, github, marquee |
| 7 | PFS always "no" | `perfect_forward_secrecy` (and `negotiated_cipher`, `ocsp_stapling`) only written in `TlsData::new` (`tls.rs:151-154`) and tests | TLSv1.3 hosts show `PFS: no` |
| 8 | Grades hide their reasons and double-count | TLS and HTTP grades measure different things, so A+ next to C is not itself the defect. TLS grade (`tls.rs:704-745`) sees no cert issues because of #6, so google = A+. Handshake rejection returns early with F and empty vulnerabilities (`tls.rs:784-797`); `Issues:` counts vulnerabilities only (`src/tui/security.rs:490-493`). HTTP grade (`http.rs:591-655`) double-penalizes missing headers via `assess_vulnerabilities` (`:553`) and grades the plain-HTTP fallback | google: Security A+ despite unread cert, HTTP C from a plain-HTTP fallback; expired.badssl.com: F, `Issues: 0`, no reason |
| 9 | Target pane clips and reorders the scanner list | iterates the `DashMap` (no order) for 8 rows under ~6 header rows (`src/tui/target.rs:424`) in a 25%-height row (`src/tui/layout.rs:13`) | HTTP and PING hidden in one run, others in the next |
| 10 | Bare-IP target looks broken | target pane IP lines come only from DNS A/AAAA (`target.rs:128-185`), which is skipped without a domain (`src/scan/dns.rs:291`); `AppState` holds only the target string (`src/types.rs:7`). TLS requires a domain (`tls.rs:394-397`). WHOIS errors red (`src/scan/whois.rs:59-63`) | 1.1.1.1 shows `❌ IPv4: no data`, Security `failed`, WHOIS `failed` |
| 11 | Traceroute flips unreached -> reached | `destination_reached` checks only `hop.responses.first()` (`src/scan/traceroute.rs:305-310`); the pane shows the first non-timeout response (`src/tui/traceroute.rs:107`), so `* 1.1.1.1` reads unreached while showing the target IP | same hops shown `✗ unreached` then `✓ reached` |
| 12 | 443 labeled `(http)` on Cloudflare | `grab_http_banner` sends plaintext `GET` to 443 (`src/scan/port.rs:396,418-436`); Cloudflare answers `400` with `Server: cloudflare` (no `/`), so `analyze_banner` returns `"http"` (`port.rs:476-487`) | 1.1.1.1 `443/tcp (http)`; google `443/tcp (https)` |
| 13 | DNS NS/TXT order reshuffles each refresh | records pushed in answer order (`dns.rs:476,516`), upstream rotates, never sorted | visible reorder every DNS cycle |
| 14 | Dead duplicate CLI | `src/cli.rs` declared in neither `lib.rs` nor `main.rs` | `rg "mod cli" src` -> no match |

### Goals

- Every pane shows truthful, stable data for domain, URL, and IP targets.
- Failures are visible with a reason; nothing sits on "checking" forever.
- `p` switches what the scanners do, not just the label.
- Each defect above gets a test that fails on the old code (break-it proof per phase).
- A pane-render test layer exists so future UI bugs get the same treatment.

### Non-Goals

- Excluded: new scanners, new panes, layout redesign beyond the target pane fix (#9).
- Excluded: emoji width handling (`⏱️` hand-padding). Not reproduced in tui-test's grid; no evidence of a defect yet.
- Excluded: making existing network-hitting unit tests (`ping.rs:706`, `tls.rs:1110`) hermetic. Pre-existing, not one of the fourteen.
- Parked: IP WHOIS via RDAP `/ip/` (netblock owner). Revisit if GEOIP's ISP/ASN line proves insufficient for IP targets. See Addendum.
- Parked: macOS live verification of #1. No mac available; covered by an arg-builder unit test per OS, written from Apple's `ping(8)` man page (assuming: `-W` in ms, no `-4`/`-6`, IPv6 via `ping6`).

## Proposed Solution

### Overview

Fix forward in the current architecture. One structural change (a protocol `watch` channel), one new test layer (`TestBackend` render helper), the rest are local fixes at the cited seams. Ordered cheapest and most mechanical first.

### Architecture

- **Scanner loop (#3):** `Scanner::run` keeps the existing `ScanState` and only flips `status = Running` while scanning. On completion it sets `result`/`error` and pushes to `history` (cap 10, unchanged). First run inserts. `docs/architecture.md` loop sketch is corrected to match.
  - Retained results must not claim freshness: a shared `status_label(&ScanState)` helper renders a `↻ refreshing` marker when `status == Running` and a result exists. The Security pane uses it in place of its unconditional `Status: analyzed` (`src/tui/security.rs:322-333`), and so does every pane with a status line.
- **Protocol switching (#4):**
  - `main.rs` creates `tokio::sync::watch::channel(initial_protocol)` and owns the `Sender` for the process lifetime. TUI mode lends it to `TuiApp`; `--no-tui`/`--debug` mode holds it and never sends.
  - `spawn_scanner_tasks` hands each scanner a `watch::Receiver<Protocol>`.
  - `Scanner::run` `select!`s on three arms: the interval tick, `rx.changed()`, and the in-flight scan future. A change mid-scan drops the in-flight future and starts a new scan with `*rx.borrow_and_update()`; a change while idle starts one immediately. Either way the interval resets.
  - `changed()` returning `Err` (sender dropped) disables that arm; the loop continues on ticks only.
  - Protocol-agnostic scanners opt out via a trait method `uses_protocol() -> bool` (default `true`) and ignore the notification. Only WHOIS qualifies (`protocol` feeds only a log line, `whois.rs:632-641`). GEOIP looks up only the selected families, so it follows `p`. (Amended during Phase 8: the reviewed draft also opted GEOIP out, which would leave IPv6 GEOIP data on screen for up to 10 minutes after `p` -> IPv4.)
  - The `p` handler cycles `AppState.protocol` and `send`s the new value. The prior result stays on screen marked `↻ refreshing` until the new result lands (consistent with #3).
- **Scan deadline and cancel safety (#4 prerequisite):**
  - Dropping a scan future must stop the work under it. Today it would not: ping and traceroute spawn children with no `kill_on_drop` (`rg kill_on_drop src` -> no match), and TLS cert analysis runs blocking OpenSSL on a `std::net::TcpStream` inside an async fn with no socket timeout (`tls.rs:494-499`).
  - Fix: `kill_on_drop(true)` on every `tokio::process::Command`; the OpenSSL path moves into `spawn_blocking` with `set_read_timeout`/`set_write_timeout` from `total_scan_timeout`, which today is only logged (`tls.rs:930`).
  - `Scanner::run` wraps every scan in `tokio::time::timeout(self.deadline())`. New trait method `deadline() -> Duration`, default 30s; TLS returns its `total_scan_timeout`. A deadline hit records `error = "timed out after Ns"`.
- **Ping (#1, #2):**
  - Arg building moves into a pure fn `ping_args(target_os, protocol, count, timeout, target) -> Vec<String>`: `"macos"` -> `-W <ms>`, anything else -> `-W ceil(secs).max(1)`. The caller passes `std::env::consts::OS`; tests pass both values.
  - `ping_args` owns the executable too, returning `(program, args)`: Linux `ping -4|-6`, macOS `ping` / `ping6` with no `-4`/`-6` (today's code emits them unconditionally, `ping.rs:340,343`).
  - When all protocols fail, `scan()` returns `Ok(PingResult)` with per-protocol `Failed` statuses and the error text. The pane maps that to `Disconnected` with the reason. The pane's existing smoothing (`calculate_state` over the last 5 results, `src/tui/connectivity.rs:87`) still decides when `disconnected` shows; a failure is recorded as a failed sample, not skipped.
- **HTTP (#5, #8 HTTP side):**
  - Keep the hostname in the URL, so SNI, `Host:` and cert validation all use the name. Pin it to the resolved IP with `reqwest::ClientBuilder::resolve(host, SocketAddr::new(ip, 0))`, built per family attempt (one pin = one `SocketAddr` = one family; it is builder-level, so the shared client in `HttpScanner::new` (`http.rs:58`) cannot carry it).
  - The pin covers only the target host. Redirects to another host (google.com -> www.google.com) resolve normally. `HttpData.target_ip` keeps meaning the pinned IP of the first request.
  - IP targets: bracket IPv6 (`https://[2607:...]/`).
  - Fallback: `http://` URL targets use their scheme as given. Domain targets try HTTPS; if it fails, try plain HTTP and store the reason in `HttpData.https_failure` and render `plain HTTP (HTTPS failed: <reason>)` with grade F. No silent fallback.
  - Missing-header penalties apply once: either in the grade or in `assess_vulnerabilities`, not both.
- **TLS (#6, #7, #8 TLS side):**
  - Expiry: `CertificateInfo.not_before/not_after` stay `DateTime<Utc>` (`tls.rs:47-48`). Convert with a pure fn `asn1_to_utc(&Asn1TimeRef) -> DateTime<Utc>`: `Asn1Time::from_unix(0)?.diff(t)` (openssl 0.10.74, `asn1.rs:200`) gives `days` + `secs` since the epoch. `days_until_expiry` keeps deriving from `not_after` (`tls.rs:851-852`). No string parsing.
  - PFS: pure fn `has_pfs(version, suite) -> bool`: true for TLS 1.3, or TLS 1.2 with an ECDHE/DHE suite. Fed from the rustls connection already held in `test_basic_connection` (`tls.rs:425-435`) via `negotiated_cipher_suite()`. Also fill `negotiated_cipher`.
  - Handshake verify errors map to a `TlsVulnerability`: expired -> `ExpiredCertificate`, unknown issuer -> new `UntrustedIssuer`, name mismatch -> new `HostnameMismatch`. The F grade then carries its reason.
  - One cause, one list: a cause that maps to a vulnerability is recorded only in `vulnerabilities`; `certificate_errors` keeps only unmapped errors. `Issues:` = `vulnerabilities.len() + certificate_errors.len()`, so an expired cert counts once.
  - IP targets (#10): both TLS paths drop their domain gates. rustls uses `ServerName::IpAddress` (`tls.rs:394-397,415`); the OpenSSL path (`tls.rs:481-484`) sets SNI only for domains and builds `SocketAddr::new(ip, port)` instead of `format!("{}:{}")` + parse (`tls.rs:494-496`), which breaks on IPv6.
- **Target pane (#9, #10):**
  - `AppState` gains the resolved IPs from `Target` resolution in `main.rs`. IP lines render from them first, DNS second; a bare-IP target shows `✅ IPv4: 1.1.1.1`.
  - An address family with no address is not a failure: a bare-IP target shows the other family as gray `IPv6: n/a` (or `IPv4: n/a`), and a domain whose DNS resolved with no AAAA (github.com) shows gray `IPv6: none`. Red `❌ ... no data` is kept for a family that was queried and errored. (Added 2026-10-29 during Phase 7: this was in the tui-test findings and was dropped from the Problem table by omission.)
  - Scanner list uses a fixed order constant. When rows are short, it collapses to a one-line summary (`8/8 ✅` style) instead of clipping silently.
- **WHOIS on IP target (#10):** returns `Ok` with new `DataSource::NotApplicable`, rendered gray as `n/a for IP targets (see GEOIP)`, not red failure.
- **Display stability (#11, #12, #13):** traceroute `responses.iter().any(|r| r.ip == target)`; port scanner never sends plaintext to TLS ports (443, 8443, 993, 995, 465) and keeps the port-map name, adding the missing map entries 8443 -> `https-alt` and 465 -> `smtps` (`get_service_name`, `port.rs:449-466`); DNS sorts each record set after lookup. Also fix the traceroute `new()` log line claiming 120s (interval is 300s, `traceroute.rs:11,127`).
- **Cleanup (#14):** delete `src/cli.rs`.

### Data Model

- `AppState`: add `resolved_ips: Vec<IpAddr>` (from `Target` resolution).
- `ScanState`: unchanged shape; lifecycle changes (mutate, not replace).
- `PingResult`: unchanged shape; now also returned for all-failed.
- `TlsData`: no new fields; `perfect_forward_secrecy` and `negotiated_cipher` become populated.
- `TlsVulnerability`: add `UntrustedIssuer`, `HostnameMismatch`.
- `HttpData`: add `https_failure: Option<String>`.
- WHOIS `DataSource`: add `NotApplicable`.
- `Scanner` trait: add `deadline() -> Duration` (default 30s) and `uses_protocol() -> bool` (default `true`).

### API Design

```rust
// scanner.rs
async fn run(&self, target: Target, protocol: watch::Receiver<Protocol>, state: Arc<Mutex<AppState>>);

// scan/ping.rs
fn ping_args(target_os: &str, protocol: Protocol, count: u32, timeout: Duration, target: &str) -> (&'static str, Vec<String>);

// scan/tls.rs
fn asn1_to_utc(t: &Asn1TimeRef) -> eyre::Result<DateTime<Utc>>;
fn has_pfs(version: ProtocolVersion, suite: SupportedCipherSuite) -> bool;

// tui test helper (cfg(test))
fn render_pane(pane: &dyn Pane, state: &AppState, w: u16, h: u16) -> String; // TestBackend buffer as text
```

### Implementation Plan

Each phase: one commit, `otto ci` green, and its new tests shown failing against the pre-fix code before the fix lands. Phase 1's smoke tests are exempt from the break-it rule: they test new infrastructure with no pre-fix code to fail against.

#### Phase 1: Pane render test helper + dead code
**Model:** sonnet
- Add `cfg(test)` `render_pane` helper in `src/tui/` using ratatui `TestBackend` (ships in ratatui 0.29; no new crate). Fake state built like the `security.rs:972-1047` fixtures.
- One smoke test per pane proving the helper renders its title.
- Delete `src/cli.rs` (#14).
- **Success criteria:** `cargo test tui::` passes with >= 9 new render tests; `test ! -e src/cli.rs`.

#### Phase 2: Scanner loop preserves state
**Model:** sonnet
- `Scanner::run` mutates in place (#3); `status_label` + `↻ refreshing` marker; correct `docs/architecture.md` loop sketch.
- **Success criteria:** a stub-scanner test asserts, during cycle 2 (`status == Running`), `result.is_some()` and `history.len() == 1`, then `history.len() == 2` after cycle 2 completes; a security-pane render of a Running state with a result contains `refreshing` and not `analyzed`.

#### Phase 3: Ping works and fails visibly
**Model:** sonnet
- `ping_args` per OS with program + flags (#1); all-failed returns `Ok` with statuses (#2); pane renders `disconnected` + reason.
- **Success criteria:** `ping_args` test asserts `("ping", [.. "-W", "5" ..])` with `-4` on Linux and `-W 5000` with no `-4`/`-6` on macOS for a 5s timeout; a `scan()` test with a nonexistent ping binary path returns `Ok` with every protocol `Failed`; after 5 failed samples a connectivity render contains `disconnected` and not `checking`.

#### Phase 4: Deterministic display
**Model:** sonnet
- DNS sort (#13), traceroute `any()` + log-line fix (#11), TLS-port banner rule (#12), fixed scanner order + collapse (#9).
- **Success criteria:** DNS test feeds NS records in two different orders and gets one identical sorted list; parse test of a `* 1.1.1.1` final hop asserts reached; banner test of a Cloudflare `400` on 443 asserts `https`; target-pane render at the 25%-row height lists scanners in the constant order or the collapsed summary, never a clipped subset.

#### Phase 5: TLS correctness
**Model:** opus
- `asn1_to_utc` (#6), `has_pfs` + cipher from rustls (#7), new vulnerability variants, one-cause-one-list rule, `Issues:` count (#8 TLS side), OpenSSL path in `spawn_blocking` with socket timeouts.
- **Success criteria:** a fixture cert built in-test with `X509Builder` (no network) round-trips `not_before`/`not_after` exactly through `asn1_to_utc`, and an already-expired one yields `ExpiredCertificate`; a security render of an expired-handshake result contains `Issues: 1` and `Certificate expired`; `has_pfs` is true for `TLS13_AES_128_GCM_SHA256` and false for TLS 1.2 `TLS_RSA_WITH_AES_128_GCM_SHA256`.

#### Phase 6: HTTP pinning and honest grading
**Model:** opus
- Hostname URL + `resolve()` pin, IPv6 brackets, visible plain-HTTP fallback, single-count header penalties (#5, #8 HTTP side).
- **Success criteria:** URL-builder test asserts host stays `github.com` for the GitHub URL target and IPv6 IP targets are bracketed; grade test asserts missing HSTS lowers the score exactly once; render test of a fallback result contains `HTTPS failed`.

#### Phase 7: IP targets first class
**Model:** opus
- `AppState.resolved_ips`, target pane from it, both TLS paths for IP targets, WHOIS `NotApplicable` (#10).
- **Success criteria:** target-pane render for `1.1.1.1` contains `✅ IPv4: 1.1.1.1` and `IPv6: n/a` with no `❌`; a domain render with an empty AAAA set contains `IPv6: none` with no `❌`; whois render for an IP target contains `n/a for IP targets`; the OpenSSL connect-address builder returns a valid `SocketAddr` for `2606:4700:4700::1111` port 443 and the TLS scan of an IP target no longer returns `Domain required`.

#### Phase 8: Protocol switching
**Model:** opus
- `watch` channel through `main.rs`, `spawn_scanner_tasks`, `Scanner::run`, `TuiApp`; `deadline()`, `uses_protocol()`, `kill_on_drop` (#4).
- **Success criteria:** with a paused tokio clock, a stub scanner whose `scan()` sleeps 60s receives `send(Protocol::Ipv4)` mid-scan and the next `scan()` call starts with `Ipv4` without the clock advancing; a stub that never returns records `timed out after 30s` once the clock advances 30s; a `uses_protocol() == false` stub is not rescanned on `send`.

#### Phase 9: Implementation audit fixes
**Model:** opus
- Added 2026-10-29 from the implementation audit (`~/.cache/review-panel/runs/vE8TbDrM/synthesis.md`). Every item is a regression or a gap against this doc's Goals, found in the committed code.
- **CN truncation panic:** `src/tui/security.rs` cuts subject and issuer CN at byte 25, and that panics on a non-ASCII char boundary. Fixing #6 made this code reachable for the first time. Truncate by chars.
- **`--no-tui` output (`src/pretty.rs`) never followed the new states.** Ping all-failed prints a success icon, and WHOIS `NotApplicable` prints as an empty successful lookup. Bring it to parity with the panes:
  - all-failed ping prints `❌` with the reason
  - WHOIS n/a prints neutral
  - an error that follows a retained result is printed
  - `https_failure` is printed
  - the HTTP grade comes from the primary result, via `as_str()`
- **Failed scans show their reason in every pane.** `status_label` also covers the no-result path:
  - `Failed` with no result renders `failed: <error>`, never `analyzing...` or `checking...` forever.
  - `Failed` with a retained result shows the error next to the old data.
  - This covers the Security pane's stuck first-scan case.
- **WHOIS deadline:**
  - The traditional whois fallback (whois-rust, synchronous, 60s socket timeout) moves into `spawn_blocking`.
  - WHOIS `deadline()` = RDAP timeout + whois timeout + slack, so the fallback runs when RDAP hangs.
- **Success criteria:**
  - A security render with a CN of 30 multi-byte chars does not panic.
  - `pretty` tests: an all-failed ping output contains `❌` and the reason; WHOIS `NotApplicable` contains `n/a` and no `✅`.
  - A security render of `Failed` with no result and error `timed out after 30s` contains that text, and not `analyzing`.
  - WHOIS `deadline()` exceeds the RDAP timeout plus the whois timeout.

## Acceptance Criteria

Live checks use a release build: `cargo build --release`, then `tui-test run --cols 200 --rows 55 -- env RUST_LOG=debug ./target/release/scan <target>`, then `tui-test close --all` after each. Debug level is needed because ping logs only at DEBUG. Log timestamps are UTC.

- [ ] **AC1** `cargo test --all-features` passes and `rg -l 'TestBackend' src` lists >= 1 file.
  - Observed on main (23f3a43): `181 passed; 0 failed`; `rg TestBackend src` -> no match (exit 1).
- [ ] **AC2** target google.com: `tui-test expect text "avg:" --timeout 15000` exits 0, and the run adds 0 `bad linger` lines to `~/.local/share/scan/logs/scan.log` (`rg -c` before vs after).
  - Observed on main: exit 1; the run added 32 `bad linger` lines.
- [ ] **AC3** target google.com, after `tui-test expect text "Status: analyzed" --timeout 15000`:
  - `tui-test expect text "https://google.com" --timeout 5000` exits 0
  - `tui-test expect text "http://142." --not --timeout 1000` exits 0
  - `tui-test expect text "Expires:" --after-text SECURITY --timeout 1000` exits 0
  - `tui-test expect text "PFS: yes" --timeout 1000` exits 0
  - Observed on main: 1, 1, 1, 1 (HTTP shows `http://142.251.45.142/`; no cert expiry; `PFS: no`).
- [ ] **AC4** target expired.badssl.com, after `Status: analyzed`: `tui-test expect text "Certificate expired" --after-text SECURITY --timeout 5000` exits 0 and `tui-test expect text "Issues: 0" --after-text SECURITY --not --timeout 1000` exits 0. Scoped because the HTTP pane renders its own issue count (`src/tui/http.rs:216`).
  - Observed on main: 1, 1.
- [ ] **AC5** target google.com: `tui-test key press p` (-> IPv4); 3s later (ping's in-flight scan is cancelled on change, see Scan deadline), `rg 'scan::ping\] scan: target=' ~/.local/share/scan/logs/scan.log | tail -1` ends in `protocol=IPv4`.
  - Observed on main: label flips (`IPv6: disabled`, exit 0), but the line 2s after the press is `... protocol=IPv4+IPv6`.
- [ ] **AC6** target 1.1.1.1: `tui-test expect text "IPv4: 1.1.1.1" --timeout 10000` exits 0.
  - Observed on main: exit 1 (pane shows `❌ IPv4: no data`).

Phase-level `cargo test` criteria cannot run on main: the tests they name are written in their phase.

## Resolved Decisions

- 2026-10-29: Test layer is `TestBackend` + text assertions on the buffer, no `insta`. Assertions target the one string each bug got wrong; snapshots of whole panes would churn on every cosmetic change and need a new dev-dep.
- 2026-10-29: On protocol change, panes keep the previous result (status Running) until the rescan lands. Clearing would reintroduce the #3 blanking.
- 2026-10-29: Plain-HTTP fallback stays, but visible and graded F. Dropping it loses data for HTTP-only sites; hiding it is what #5 is.
- 2026-10-29: Acceptance criteria scope `Expires:` to the Security pane with `--after-text SECURITY`: unscoped, it matches WHOIS `Expires:` and passed on main (exit 0), a false green.
- 2026-10-29: WHOIS for IP targets is a neutral n/a, not RDAP `/ip/`. GEOIP already shows ISP and ASN.

- 2026-10-29 (panel round 1, both seats): `watch` channel confirmed. Staff's in-flight blocker accepted: the design now cancels in-flight scans on change and bounds every scan with `deadline()`, so AC5's 3s holds by construction.
- 2026-10-29 (panel round 1): rejected Gemini's Rollback/Migration section (stateless CLI, one repo, rollout already names `bump`). Rejected `log::warn!` per plain-HTTP fallback: the pane already shows it graded F, and a warn every 60s cycle is log noise.
- 2026-10-29 (panel round 1): AC2 keeps `avg:` rather than a numeric-latency regex. `avg:` renders only in the `Connected` state (`connectivity.rs:424`), which already requires a parsed latency.

## Alternatives Considered

### Re-read protocol from `AppState` each cycle (#4)
- **Description:** `run` reads `state.protocol` at each tick; no channel.
- **Pros:** no signature change.
- **Cons:** TLS ticks every 300s, WHOIS every 1h, traceroute every 300s: `p` would take up to an hour to land.
- **Why not chosen:** fails the "responsive" requirement in `docs/ipv4-ipv6-first-class-support.md`.

### Abort and respawn scanner tasks on `p` (#4)
- **Description:** keep `JoinHandle`s, abort all, call `spawn_scanner_tasks` again.
- **Pros:** no change to `Scanner::run`.
- **Cons:** loses in-flight state and adds moving parts in the TUI loop. Today it would also orphan ping/traceroute children (`rg kill_on_drop src` -> no match).
- **Why not chosen:** the watch channel is smaller and cancellation-free.

### Disable cert validation for HTTPS-by-IP (#5)
- **Description:** keep IP URLs, `danger_accept_invalid_certs(true)`.
- **Cons:** measures the wrong virtual host and hides cert problems.
- **Why not chosen:** abandons the feature's value.

## Technical Considerations

### Dependencies
- No new crates. `reqwest::ClientBuilder::resolve` (0.12.24, no feature gate), `openssl::asn1` diff/compare (0.10.74), rustls `negotiated_cipher_suite` (0.23.34), `tokio::sync::watch`, ratatui `TestBackend` (0.29) all present.

### Performance
- HTTP builds one `reqwest::Client` per scan (every 60s). Negligible against the request itself.

### Security
- Pinning keeps full cert validation on; nothing is disabled.

### Testing Strategy
- Unit tests at each seam (pure fns: `ping_args`, banner analysis, hop parse, grade).
- Pane render tests through `render_pane` over fake `AppState`.
- Every phase demonstrates its tests failing on the pre-fix code (revert the fix locally, run, restore).
- Live: the acceptance criteria above, run with tui-test after the last phase.

### Rollout Plan
- Single repo, no cross-repo blast radius. Phases land in order on a branch; release via the normal `bump` path after the live acceptance run.

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| macOS `-W` semantics differ from assumption | Low | Med | per-OS unit test; live check parked until a mac is available |
| Cert-fixture generation in tests needs `openssl` crate APIs only | Low | Low | build the X509 in-process with `openssl::x509::X509Builder`, no shell-out |
| `select!` on watch + interval drops a tick | Low | Low | Phase 8 test asserts rescan timing |
| Dropping a scan future leaves work running | Med | Med | `kill_on_drop`, `spawn_blocking` + socket timeouts; Phase 8 deadline test |

## Open Questions

None.

## Addendum: parked

- **IP WHOIS via RDAP `/ip/`**: would show netblock owner and allocation dates for IP targets. Needs a different result shape than the domain-oriented `WhoisResult`. Parked until GEOIP's ISP/ASN proves insufficient.

## Review Pass Log

- Pass 1 (draft): structure, 14-row problem table from the research brief, 8 phases.
- Pass 2 (correctness): `ping_args` took a nonexistent `Os` type -> `target_os: &str`; AC3 `Expires:` matched WHOIS (false green on main) -> scoped to SECURITY; AC5 relied on INFO log where ping is silent -> debug run.
- Pass 3 (clarity): live-check harness stated once above the criteria; UTC log timestamps noted.
- Pass 4 (edge cases): protocol change during an in-flight scan; interval reset after a forced rescan; redirects off the pinned host.
- Panel round 1 (Gemini + Codex): 7 must-fix and 9 cheap-win folded in (in-flight cancel + deadline, Phase 2/5/7 criteria, data-model variants and fields, staleness marker, macOS flags, port map, scoped AC4). 2 rejected with rationale under Resolved Decisions. Synthesis: `~/.cache/review-panel/runs/ycJdUxfV/synthesis.md`.
- Pass 5 (excellence): no-new-crate check against Cargo.lock versions; non-goals split into excluded vs parked.

## References

- tui-test session evidence: captured screens in the session scratchpad; `~/.local/share/scan/logs/scan.log`
- `docs/ipv4-ipv6-first-class-support.md`, `docs/architecture.md`
