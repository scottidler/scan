# Implementation Notes: Runtime Bug Fixes

## Phase 1: Pane render test helper + dead code

(Reconstructed by the orchestrator from the Phase 1 report: the Phase 2 run recreated this file and the original Phase 1 section was lost.)

### Design decisions
- `render_pane(&dyn Pane, &AppState, w, h, focused) -> String` (`src/tui/testing.rs`, `#[cfg(test)] pub mod testing` in `src/tui/mod.rs`): takes `focused` because `Pane::render` does.
- Fixtures are bare `AppState::new("example.com")`: a title smoke render needs nothing richer than the `security.rs` fixtures provide.

### Deviations
- `#[allow(clippy::double_must_use)]` on the `Scanner` trait (`src/scanner.rs`): rust 1.99 clippy flags the `async_trait` expansion and fails `otto ci` on unchanged main (verified by stashing). Not a design-doc item; required for green CI.

### Tradeoffs
- 9 per-pane title smoke tests plus 1 negative test, over the 9 required.

### Open questions
- None. (Lint allow vs toolchain/`async_trait` change: kept the allow; pre-existing, out of scope.)

## Phase 2: Scanner loop preserves state
### Design decisions
- `status_label(&ScanState, running, complete) -> (&'static str, Color)` in new `src/tui/status.rs`, re-exported from `tui`: one helper replaces seven copy-pasted status `match` blocks. `Running` with a retained result yields `↻ refreshing` (`REFRESHING_LABEL`); `Running` without one yields the pane's first-scan text.
- `Scanner::run` (`src/scanner.rs`) flips `status = Running` via `get_mut`, inserting a fresh `ScanState` only on the first cycle. Result, error and history are untouched until the scan completes; a failed cycle keeps the last good result and history.
- Security pane takes its header from the `tls` scanner's state (`tls_status_label`) instead of the unconditional `analyzed`.
- `docs/architecture.md` loop sketch corrected: in-place Running, `max_history()` cap (was a stale `100`), plus a rationale bullet.
- Break-it proof: with the old `run()` and the old unconditional `analyzed` header, 4 new tests failed (`second_cycle_keeps_result_and_history_while_running`, `failed_cycle_keeps_result_and_history`, `history_is_capped_at_max_history`, `render_running_state_with_result_shows_refreshing_not_analyzed`); all pass after the fix.
### Deviations
- Connectivity pane not switched to `status_label`: its status derives from `calculate_state` over the last 5 pings (smoothing), not from `ScanState.status`. Panes switched: dns, geoip, http, ports, traceroute, whois, security.
- Stub-scanner test uses a real 20ms interval and abort rather than a paused clock: tokio's `test-util` feature is not enabled and adding it is outside this phase.
### Tradeoffs
- Helper takes each pane's first-scan and complete strings as arguments vs a fixed vocabulary: keeps existing wording (`resolving...`, `traced`, ...).
- Extra `history_is_capped_at_max_history` test pins the cap the rewrite touches.
### Open questions
- None.

## Phase 3: Ping works and fails visibly
### Design decisions
- `ping_args(target_os, protocol, count, timeout, target) -> (&'static str, Vec<String>)` is a pure pub fn - src/scan/ping.rs - Linux: `ping -4|-6 -c N -W ceil(secs).max(1)`; macOS: `ping`/`ping6`, no family flag, `-W <ms>`.
- `PingScanner::with_program(..)` builder override - src/scan/ping.rs - gives the "nonexistent ping binary" scan() test a seam without changing the default path.
- `scan()` always returns `Ok(PingResult)`; all-failed is logged at error and carried in per-protocol `Failed`/`NoAddress`/`ToolMissing` statuses - src/scan/ping.rs:scan.
- Connectivity pane shows `disconnected: <first failure reason>` (reason via `failure_reason`) - src/tui/connectivity.rs - failed samples already feed `add_result`, so the existing 5-sample smoothing decides when it shows.
### Deviations
- Pane also maps `(Disconnected, Checking)` and `(Checking, Disconnected)` to `disconnected`: with `p` set to a single family the other protocol is `NotQueried` forever, which would leave the pane on "checking" despite a dead link. Same intent as the spec (nothing sits on "checking").
- Old label `no connectivity` renamed to `disconnected` to match the success criterion.
- `test_no_target_for_protocol` inverted and renamed `test_no_target_for_protocol_returns_failed_status`; `test_protocol_aware_ipv6_ping` now tolerates an all-failed Ok on hosts without an IPv6 loopback (this host has none; it previously passed only via the tolerated Err arm).
### Tradeoffs
- Reason text is the raw per-protocol failure message, truncated only by the pane width, vs a curated short reason: keeps the real cause visible without a mapping table.
### Open questions
- None.

## Phase 4: Deterministic display
### Design decisions
- `DnsResult::sort_records` sorts every record set (A/AAAA by address, strings lexically, MX by priority then exchange, SRV/CAA/SOA by field tuples) and is called once at the end of the lookup in src/scan/dns.rs. One choke point covers all current and future sets.
- Traceroute `destination_reached` uses `responses.iter().any(...)`; the `new()` log line now interpolates the constants so it cannot drift again (src/scan/traceroute.rs).
- `TLS_PORTS`/`is_tls_port` is checked first in `grab_banner`: TLS ports (443, 8443, 993, 995, 465) get no banner and no plaintext write, so `detect_service` falls through to the port-map name (src/scan/port.rs). `get_service_name` gained 8443 -> `https-alt`, 465 -> `smtps`.
- Target pane: `SCANNER_DISPLAY_ORDER` constant + `ordered_scanner_keys` (unknown keys appended sorted); full list only when spacer + Status + every row fits, otherwise a single `N/M ✅ [k 🔄] [k ❌]` line (src/tui/target.rs).
### Deviations
- When collapsed and header plus summary still exceed the inner height, the Protocol line is dropped so the summary stays visible (a 24-row terminal's 25% top row is 6 rows, inner height 4). Not in the spec; needed so the summary is never the clipped thing.
- Collapsed mode omits the spacer and the separate `Status:` line; the summary replaces it.
### Tradeoffs
- All-or-nothing collapse vs. showing as many rows as fit plus "+N more": the spec forbids a clipped subset and all-or-nothing is the simplest predictable rule.
- Port test drives `detect_service(stream, 443)` against an ephemeral listener (the port argument, not the socket, selects the rule) vs. binding privileged port 443.
### Open questions
- None.

Break-it evidence: with the fixes reverted (first()-only traceroute check, TLS skip disabled, sort bodies removed, collapse forced off and constant order disabled) 6 tests fail: test_sort_records_is_order_independent, test_parse_marks_reached_when_target_not_first_response, test_tls_port_never_sends_plaintext_and_keeps_port_name, test_short_pane_collapses_never_clips_subset, test_full_list_uses_constant_order, test_tall_pane_shows_every_scanner_and_no_summary. Restored: 216 pass.

## Phase 5: TLS correctness
### Design decisions
- `asn1_to_utc(&Asn1TimeRef) -> Result<DateTime<Utc>>` is a pub free fn in src/scan/tls.rs: `Asn1Time::from_unix(0)?.diff(t)?` then `days*86400 + secs` -> `DateTime::from_timestamp`. The old `asn1_time_to_datetime` string parser is deleted. It expected `YYMMDDHHMMSSZ`, but `Asn1Time`'s `Display` is `Mon DD HH:MM:SS YYYY GMT`, so every certificate failed to parse. `parse_certificate` dropped `&self` so the blocking pool and the tests can call it.
- `has_pfs(ProtocolVersion, rustls::CipherSuite)` returns true for every TLS 1.3 suite and for a TLS 1.2 IANA name starting `TLS_ECDHE_`/`TLS_DHE_`. The rustls handshake in `test_basic_connection` feeds it from `negotiated_cipher_suite().suite()` and also fills `negotiated_cipher` through `cipher_suite_info`, which splits the IANA name into kx/auth/enc/mac.
- `test_basic_connection` now returns `HandshakeOutcome::{Established(Handshake), Rejected(TlsVulnerability)}`. `handshake_rejection` downcasts the tokio-rustls `io::Error` to `rustls::Error` and `vulnerability_for_handshake_error` maps Expired/ExpiredContext -> `ExpiredCertificate`, UnknownIssuer -> `UntrustedIssuer`, NotValidForName/NotValidForNameContext -> `HostnameMismatch`. Every other error still goes through the unchanged `Err` path: a `Connection failed: ...` certificate error and an early return.
- On `Rejected`, phase 2 is skipped (the handshake would just be rejected again) and phase 3 still runs, so the OpenSSL pass (verify NONE) fills expiry, subject and issuer for the bad cert. `connection_successful` stays false, so the grade is F, and the reason now sits in `vulnerabilities`.
- One cause, one list: `merge_vulnerabilities(handshake, detected)` keeps the handshake cause and appends each detected cause not already present. An expired cert, rejected by rustls and also detected from `not_after`, therefore counts once.
- `TlsData::issue_count()` = `vulnerabilities.len() + certificate_errors.len()`. The Security pane's `Issues:` uses the primary result's `issue_count()` instead of `TlsResult::total_vulnerabilities()`, which summed both stacks and ignored certificate errors.
- The OpenSSL path moved into `spawn_blocking` behind a new async `analyze_certificate` wrapper. `analyze_certificate_with_openssl` became an associated fn on owned data and sets `set_read_timeout`/`set_write_timeout` to `total_scan_timeout` after `connect_timeout`.
- Test fixtures live in `#[cfg(test)] pub(crate) mod fixtures` in src/scan/tls.rs: `leaf_certificate(not_before, not_after)` is an EC P-256 leaf signed by a separate CA key, so it is not self-signed. `expired_handshake_result()` runs the same functions in the same order as `perform_tls_scan_for_ip`. No network.
### Deviations
- `has_pfs` takes `rustls::CipherSuite` (the IANA code enum), not `SupportedCipherSuite` as the API Design block says. rustls ships no static-RSA suite, so the success criterion's `TLS_RSA_WITH_AES_128_GCM_SHA256` cannot exist as a `SupportedCipherSuite`. The caller passes `SupportedCipherSuite::suite()`, so the effect is the same at the correct seam.
- `asn1_to_utc` returns `eyre::Result` (as the API Design block says), not the bare `DateTime<Utc>` in the Architecture prose: `from_unix`/`diff` are fallible.
- `merge_vulnerabilities` also drops `UntrustedIssuer` when `SelfSignedCertificate` is present: a self-signed leaf is why rustls reports an unknown issuer, so it is one cause and would otherwise count twice. The spec does not say this; it is the one-cause rule applied.
- `certificate_valid` is now false when the handshake was rejected. Before, the pane showed `Valid: yes` next to `Certificate expired`. Not named in the spec; the claim was false.
- The Security pane's TLS list now shows the primary result's vulnerabilities followed by its certificate errors, so every counted issue is listed. The heading is renamed `⚠️ TLS Vulnerabilities` -> `⚠️ TLS Issues` because it now includes certificate errors. Before, the list came from both stacks (`get_all_vulnerabilities`), so a dual-stack expired cert would have been listed twice under `Issues: 1`.
- The `Domain required` gates and the `format!("{}:{}")` address building stay as they are; Phase 7 owns them.
### Tradeoffs
- The pane counts the primary (IPv4-preferred) result only, not both stacks: the rest of the pane already describes the primary result, and summing stacks double-counts one server-side cause.
- TLS 1.3 `key_exchange` is recorded as `ECDHE` because the ring provider only offers ECDHE groups. `negotiated_key_exchange_group()` would be exact, but nothing renders the field.
### Open questions
- AC4's first command, `tui-test expect text "Certificate expired" --after-text SECURITY --timeout 5000`, exits 1 at 200x55 because the Security pane holds 44 content lines in a 20-line viewport, so the `TLS Issues` section is below the fold. After 30 `j` presses (the pane has focus at startup) the same command exits 0. Should AC4 be run with a scroll step, or should the TLS issue list move up next to `Issues:`?

Break-it evidence: with each fix reverted on its own: old string ASN.1 parser -> 6 fail (both asn1 tests, both fixture-expiry tests, expired_handshake_counts_one_issue_and_grades_f, render_expired_handshake_counts_one_issue_and_names_it). `has_pfs` always false -> 2 fail. Handshake errors unmapped -> 4 fail. Pane count back on `total_vulnerabilities()` -> 1 fail (render_issue_count_is_primary_vulnerabilities_plus_certificate_errors). No dedupe in merge -> 3 fail. `set_read_timeout` removed -> openssl_analysis_gives_up_on_a_silent_server_after_io_timeout fails (hung past 5s). Restored: 231 pass.

### Phase 5 amendment (supersedes the Phase 5 open question and the `TLS Issues` heading deviation)
- Orchestrator ruling: AC4 stays as written. A reason below the fold at 200x55 is the same defect as #8 (an F grade with no visible reason), so the fix belongs in Phase 5.
- The TLS issue list (the same items `Issues:` counts) now renders as bullets directly under the `⚠️ Issues:` line, before HTTP Security. The separate `⚠️ TLS Issues` section at the bottom of the pane is gone. src/tui/security.rs:build_content_lines.
- New test `render_expired_handshake_reason_visible_without_scrolling` renders the expired-handshake result plus a no-headers HTTP result at 68x22 (20 inner lines, the Security pane at 200x55) and asserts `Certificate expired` with no scroll. It failed on the 1dc2113 layout ("reason below the fold") and passes after the move. 232 tests pass.
- Live at 200x55, unscrolled. expired.badssl.com: `Certificate expired` after SECURITY exits 0 and `Issues: 0 --not` exits 0. google.com: `Expires:` and `PFS: yes` both exit 0.

## Phase 6: HTTP pinning and honest grading
### Design decisions
- `request_plan(&Target) -> Result<RequestPlan>` (src/scan/http.rs) is a pure fn returning `primary` plus `plain_http_fallback: Option<Url>`. URL targets: the URL as given, no fallback (so `http://` keeps its scheme and an `https://` URL target never downgrades). Domain targets: `https://<name>/` then `http://<name>/`. IP targets: same pair, IPv6 bracketed (`https://[2606:4700:4700::1111]/`).
- `HttpScanner::pinned_client(host, ip)` builds one `reqwest::Client` per family attempt and calls `.resolve(host, SocketAddr::new(ip, 0))` only when the URL host is a name (`pinned_host`); an IP-literal host needs no pin. Port 0 means reqwest keeps the URL's port. The shared `client` field on `HttpScanner` is gone; the struct keeps only `timeout`.
- `http_protocol` takes the IP from `primary_ip_for_protocol` instead of `network_target_for_protocol` (which returned a string and fell back to the domain). `HttpData.target_ip` is that pinned IP, set in `perform_scan` for the first request and kept on the fallback result.
- `scan_plan(&RequestPlan, IpAddr)` is the seam the tests drive: it requests `primary`; on error with a fallback, it requests the fallback and sets `https_failure = Some(root_cause(err))` and `security_grade = F`. Both failing returns `HTTPS failed: <a>; plain HTTP failed: <b>`. `root_cause` is the last entry of the eyre chain, so the pane shows `invalid peer certificate: UnknownIssuer` rather than reqwest's `error sending request for url (...)` wrapper.
- `calculate_security_score` split out of `calculate_security_grade` so the single-count rule is testable on the number, not the bucket. The vulnerability loop matches every variant exhaustively; header/CSP/CORS-derived variants add nothing, `InformationDisclosure` keeps a 5-point penalty (`INFORMATION_DISCLOSURE_PENALTY`, renamed from `OTHER_VULN_PENALTY`).
- HTTP pane (src/tui/http.rs) renders `⚠️ plain HTTP (HTTPS failed: <reason>)` in red as the first content line under the status header, and the paragraph now wraps, so the reason stays inside the 50x19 pane at 200x55.
### Deviations
- Single-count applies to `WeakCsp` and `InsecureCors` too, not only the missing-header variants the spec names. Both were scored twice the same way (CSP strength -15 plus `WEAK_CSP_VULN_PENALTY` -15; CORS Dangerous -25 plus `INSECURE_CORS_VULN_PENALTY` -20), which is the #8 double-count. The three `*_VULN_PENALTY` constants are deleted.
- IP targets get the HTTPS-then-plain-HTTP fallback, though the spec says "Domain targets". The pre-fix code treated domain and IP targets alike, and an IP target with no IP SAN would otherwise show HTTP failed with no data; the fallback is visible and graded F either way.
- The spec's per-attempt client lives in a new `pinned_client` helper and the scan body in `scan_plan`, not in `perform_http_scan_for_target` (renamed `perform_http_scan_for_ip`, now a two-line wrapper). Same effect, testable seam.
- The HTTP pane paragraph gained `Wrap { trim: false }`, which also wraps long redirect lines instead of clipping them. Not named in the spec; needed to keep the reason visible.
### Tradeoffs
- Fallback/pinning tests use a loopback `TcpListener` and a `pinned.invalid` hostname instead of the network: the `Host:` header proves the name is kept and the successful connect proves the pin, with no DNS. The HTTPS leg fails because the server answers a ClientHello with plain HTTP.
- Domain targets with a port (`host:8080`) still request the default ports, as before; `request_plan` ignores `Target.port` for bare targets. Not in this phase's scope.
### Open questions
- `get_best_security_grade` still picks the better of IPv4/IPv6, so a dual-stack target where only one family fell back can show the other family's grade next to the primary result's `HTTPS failed` line. Should the pane grade come from the primary result instead?

Break-it evidence: request_plan reverted to the old `set_host(ip)` / unbracketed IPv6 -> 3 of 4 request_plan tests fail (domain case still passes). Old vulnerability double-count restored for HSTS -> `missing_hsts_lowers_score_exactly_once` fails (25 vs 15). Fallback marking removed -> `https_failure_falls_back_to_plain_http_visibly_with_grade_f` fails. `.resolve()` removed -> `pinned_request_keeps_hostname_and_connects_to_pinned_ip` fails. Pane line removed -> `render_plain_http_fallback_names_https_failure_and_grade_f` fails. Restored: 244 pass.

Live at 200x55 (release build): google.com `Status: analyzed` 0, `https://google.com` 0, `http://142.` --not 0; HTTP pane shows `https://google.com/ → https://www.google.com/ (301)`, Grade B (was C via plain HTTP). `https://github.com/scottidler/scan`: HTTP pane `Status: 200`, Grade APlus, not failed.

### Phase 6 amendment (supersedes the Phase 6 open question on `get_best_security_grade` and the domain-port tradeoff wording)
- Orchestrator ruling: the HTTP pane's grade comes from the primary result, the same one whose `HTTPS failed` line renders. Best-of across families hides a downgrade (the #5/#8 defect class), and it matches Phase 5's Security pane using the primary result. src/tui/http.rs render no longer calls `get_best_security_grade`; it reads `primary_data.security_grade`.
- The pane rendered the grade with `format!("{:?}")`, so A+ showed as `APlus`. This was pre-existing: main (23f3a43) src/tui/http.rs has the same `format!("{:?}", security_grade)`. Added `SecurityGrade::as_str()` (`A+`, `A`, ... `F`) to src/scan/http.rs, mirroring the TLS `SecurityGrade::as_str`, and the pane uses it.
- New tests: `render_grade_comes_from_primary_result_not_best_family` (dual-stack fixture, IPv4 fell back with F, IPv6 has A; pane must show `Grade: F` and no `Grade: A`) and `render_a_plus_grade_as_a_plus` (`Grade: A+`, no `APlus`), plus `security_grade_labels`. Both render tests failed against the 8972c6d pane code and pass now. 247 tests pass.
- Out of scope (not an open question): domain targets with a port (`host:8080`) still request the default ports; `request_plan` ignores `Target.port` for bare targets, as before this phase.
- Live, 200x55, `https://github.com/scottidler/scan`: `Status: analyzed` 0, `Status: 200` 0, `Grade: A+` 0, `APlus` --not 0; HTTP pane shows `🔒 Grade: A+`.

## Phase 7: IP targets first class
### Design decisions
- `AppState.resolved_ips: Vec<IpAddr>` (src/types.rs), empty from `AppState::new`; src/main.rs fills it from `target.all_ips()` after `Target::resolve`, so an IP target carries its literal and a name carries the system resolver's answer.
- Target pane (src/tui/target.rs): the five duplicated per-DNS-state IPv4/IPv6 blocks collapse into `address_line(state, AddressFamily)`. Order: protocol disabled -> `⚫ disabled`; else first `resolved_ips` entry of that family -> `✅ IPvN: <ip>`; else `address_from_dns`, which keeps the old DNS-state texts (`no data`, `resolving...`, `resolution failed`, `waiting to resolve...`, `initializing...`, `error`).
- TLS (src/scan/tls.rs): two pure fns. `connect_addr(&str, u16) -> Result<SocketAddr>` parses the IP and builds `SocketAddr::new(ip, port)`; both the rustls and OpenSSL paths use it, so IPv6 needs no brackets. `server_name(Option<&str>, IpAddr) -> Result<ServerName>` returns the domain's DNS name or `ServerName::IpAddress`. Both `Domain required` gates are gone.
- OpenSSL path: `analyze_certificate_with_openssl(sni: Option<&str>, addr: SocketAddr, ..)` uses `connector.configure()` with `set_use_server_name_indication(sni.is_some())` and `set_verify_hostname(false)` (verification is already `NONE` there; the pass only reads the chain).
- WHOIS: `DataSource::NotApplicable` and `WhoisResult::not_applicable(target)` (src/scan/whois.rs); `scan_whois` returns it as `Ok` when the target has no domain, with no risk indicators. The pane (src/tui/whois.rs) renders `📋 Status: n/a` gray, `🎯 Target: <ip>`, `📡 Source: n/a for IP targets (see GEOIP)` gray, and skips privacy/risk/source rows.
### Deviations
- `src/tui/testing.rs` `render_pane` now skips the continuation cell after a double-width glyph, so `✅ IPv4: 1.1.1.1` matches as a terminal shows it (the buffer otherwise yields `✅  IPv4`). Not named in the spec; required for the success criterion's exact string. No prior test asserted text after an emoji; all pass.
- The WHOIS pane's `Status:` header reads gray `n/a` for a `NotApplicable` result instead of the green `retrieved` from `status_label`. The spec names only the source line; `retrieved` would claim data that was never fetched.
- The spec's `ServerName::IpAddress` and `SocketAddr::new` live in the `server_name` / `connect_addr` helpers rather than inline at `tls.rs:415/494`. Same effect, testable seam.
### Tradeoffs
- `connect_addr` fails loudly when handed a hostname (`TLS target is not an IP address`) instead of resolving it. `tls_protocol` checks `supports_protocol` first, so an IP is always present; the old rustls path would have silently resolved a hostname string via `TcpStream::connect(&str)`.
- The IP-target TLS test drives `perform_tls_scan_for_ip` against a loopback OpenSSL server with a self-signed `fixture.test` cert (`fixtures::spawn_loopback_tls_server`), no network. rustls rejects the cert (unknown issuer) and the OpenSSL pass still reads it, which proves both paths get past the old gate.
### Open questions
- A bare IPv4 target shows `❌ IPv6: no data` in red (DNS is skipped for IP targets, so the result is empty). Accurate but alarming for a target that cannot have an IPv6 address; should an IP target render the other family as gray `n/a`?

Break-it evidence: with the fixes reverted in place (pane ignores `resolved_ips`, WHOIS `Err` on no domain, pane n/a branch disabled, `connect_addr` back to `format!("{}:{}")` + parse, both `Domain required` gates restored), 7 of the 8 new tests fail: `connect_addr_builds_ipv6_socket_addr_without_brackets`, `connect_addr_rejects_a_hostname`, `ip_target_tls_scan_reaches_the_certificate`, `ip_target_scan_is_ok_and_not_applicable`, `bare_ipv4_target_renders_its_address_without_dns`, `bare_ipv6_target_renders_its_address`, `ip_target_renders_not_applicable_not_failure`. The eighth, `resolved_address_respects_disabled_protocol`, guards the disabled path and passes either way. Restored: 257 pass.

Live, release build, 200x55, `scan 1.1.1.1`: `IPv4: 1.1.1.1` 0, `n/a for IP targets` 0, `Domain required` --not 0. Target pane `▶ ✅ IPv4: 1.1.1.1`; WHOIS `Source: n/a for IP targets (see GEOIP)`; Security `Status: analyzed`, TLSv1.3, `Subject: cloudflare-dns.com`, `Grade: A+`, `Issues: 0`.

### Phase 7 amendment (supersedes the Phase 7 open question on `❌ IPv6: no data` for IP targets)
- Orchestrator ruling, now in the design doc's Target pane bullet and Phase 7 success criteria: a family with no address is neutral, not a failure. src/tui/target.rs `address_from_dns` now returns, after `resolved_ips` comes up empty for the family: gray `⚫ IPvN: n/a` when `state.target` parses as an IP; for DNS results, `✅` on a record, red `❌ no data` only for `QueryStatus::Failed`/`Timeout`, gray `none` for `NoRecords` (and a zero-record `Success`), gray `not queried` for `NotQueried`.
- Inverted test: `dns_records_fill_in_when_resolution_has_no_address` asserted red `❌ IPv6: no data` for an AAAA left at default `NotQueried`; it now asserts gray `IPv6: not queried` and no `❌`.
- New tests: `bare_ip_target_shows_other_family_as_neutral_na` (1.1.1.1 -> `IPv6: n/a`, 2606:4700:4700::1111 -> `IPv4: n/a`, no `❌`), `domain_with_empty_aaaa_shows_neutral_none` (`IPv6: none`, no `❌`), `queried_family_that_errored_stays_red` (`Failed` and `Timeout` -> `❌ IPv6: no data`). Against the 276ee99 pane code the two neutral tests fail and the red guard passes; with the change all 15 target-pane tests pass, 260 total.
- Deviation: `not queried` for `NotQueried` is not named in the ruling. It is neither an error nor a known-empty set, so it gets its own gray text rather than borrowing `none`.
- Live, release build, 200x55: `scan 1.1.1.1` `IPv4: 1.1.1.1` 0, `IPv6: n/a` 0, `n/a for IP targets` 0, `Domain required` --not 0; `scan github.com` `IPv6: none` 0 (pane: `▶ ✅ IPv4: 20.29.134.23`, `▶ ⚫ IPv6: none`).

## Phase 8: Protocol switching
### Design decisions
- `Scanner::run(target, watch::Receiver<Protocol>, state)` (src/scanner.rs): an idle `select!` on `ticker.tick()` and `protocol_rx.changed()`, then a scan loop that pins `tokio::time::timeout(self.deadline(), self.scan(..))` and `select!`s it against `changed()`. A change mid-scan drops the pinned future and loops with `*borrow_and_update()`; a change while idle falls into the same loop. Both paths call `ticker.reset()`, so the next tick is a full interval after the change.
- The scan future is pinned outside the inner `select!`, so a `changed()` `Err` mid-scan only flips `follow_protocol = false` and keeps awaiting the same in-flight scan. Without the pin, the sender dropping would cancel the scan.
- `mark_running` and `record_outcome` are free fns split out of `run`. The `Ok`/`Err` bodies are unchanged from Phase 2. A deadline hit maps to `Err(eyre!("timed out after {}s"))` and goes through the same `Err` path, so it keeps the last good result and history.
- `deadline()` defaults to `DEFAULT_SCAN_DEADLINE` (30s), and `TlsScanner` returns `total_scan_timeout`. `uses_protocol()` defaults to `true`, and `WhoisScanner` returns `false`. For an opted-out scanner the `changed()` arm is disabled from the start, but each scan still reads the current protocol.
- `kill_on_drop_command(program)` (src/scan/mod.rs) is the one constructor for `tokio::process::Command`. Ping (`which` + `ping`) and traceroute go through it, so a new call site gets `kill_on_drop(true)` by using the same helper. `rg 'Command::new' src` now shows only this helper and a sync `std::process` test call in traceroute.
- main.rs creates the `watch::channel` from `AppState.protocol` and keeps `protocol_tx` in `main`'s scope. TUI mode lends `&protocol_tx` to `TuiApp::run`, and debug/no-tui mode holds it until the process exits without sending. `spawn_scanner_tasks` gives each task its own `Receiver` clone.
- The `p` handler is now `tui::switch_protocol(&Mutex<AppState>, &watch::Sender<Protocol>) -> Protocol`. It cycles `AppState.protocol` and sends the new value. A send with no receivers logs at error (`protocol_change_not_delivered`) and still updates the label.
- docs/architecture.md: the loop sketch now shows the select/cancel/deadline shape and the two new trait methods, and the rationale list gains the watch-channel bullet. Without this, the sketch Phase 2 corrected would be wrong again.
### Deviations
- GeoIP keeps `uses_protocol() == true`. The spec and the phase prompt both opt it out, with the reason "`protocol` feeds only a log line (`whois.rs:632-641`)". That reason is true for WHOIS and false for GeoIP. `GeoIpScanner::scan` branches on the protocol and geolocates only the selected families (`geoip_protocol(target, Protocol::Ipv4)` / `Ipv6` / both via `tokio::join!`). With GeoIP opted out, the pane would keep showing the IPv6 location for up to 10 minutes after `p` -> IPv4, which is the #4 defect in a single pane. The cost of following the protocol is at most two ip-api requests per `p` press.
- `TuiApp::run` takes `&watch::Sender<Protocol>` as a parameter instead of storing the sender in `TuiApp`. That matches "lends" (`main` keeps ownership), and `TuiApp::new` keeps its signature. examples/tui_test.rs builds its own channel to fit the new signature.
- The kill-on-drop is enforced through a helper rather than written inline at each call site. Same effect, and one place to check.
### Tradeoffs
- On a mid-scan change the cancelled scan records nothing, and the status stays `Running` until the replacement scan lands. The previous result stays on screen as `↻ refreshing`, per the resolved decision, and `history` gets no entry for a scan that never finished.
- `scan_count` counts attempts, cancelled ones included, so the `count=` in the debug log matches the `scan_cycle_starting` lines.
- The deadline test sleeps 30s on the paused clock, then yields ten times so the run task can record the timeout. The alternative was a notify hook in `record_outcome`, which would put a test seam into production code.
- The ping kill-on-drop test drives `PingScanner::with_program` with a temp shell script that writes its pid and `exec sleep 60`. It aborts the scan task and then requires `ps -o stat=` to report the pid as gone or a zombie. It is Linux-only (`#[cfg(target_os = "linux")]`) and takes about 50ms.
### Open questions
- GeoIP opt-out (see Deviations): kept following the protocol because it uses it. Confirm, or amend the design doc's Architecture bullet to name WHOIS only.

Success criteria (all `#[tokio::test(start_paused = true)]` in src/scanner.rs):
- PASS `protocol_change_mid_scan_restarts_scan_with_new_protocol_immediately`: the stub's `scan()` sleeps 60s; `send(Ipv4)` mid-scan; the second `scan()` call gets `Ipv4` at the same `tokio::time::Instant` as the first, and history is empty (cancelled scan recorded nothing).
- PASS `scan_past_deadline_records_timeout`: a stub that never returns records `error == "timed out after 30s"`, status Failed, after 30s on the clock.
- PASS `protocol_agnostic_scanner_is_not_rescanned_on_change`: a `uses_protocol() == false` stub gets no second call within 60s of `send(Ipv4)`.
- Extra: `protocol_change_while_idle_scans_immediately_and_resets_interval` (an idle change scans at once, and the next tick comes 3600s after the change), `dropped_sender_keeps_scanning_on_ticks`, `default_deadline_and_protocol_use`, `deadline_is_the_total_scan_timeout` (tls), `whois_ignores_protocol_changes`, `kill_on_drop_command_sets_kill_on_drop`, `dropping_an_in_flight_scan_kills_the_ping_child`, `switch_protocol_cycles_state_and_notifies_scanners`, `switch_protocol_without_listeners_still_updates_state`. 272 tests pass.

Break-it evidence: each fix was reverted on its own and the tests rerun. With both `changed()` arms gated `if false` (the old behavior, where the protocol is read only at tick time), `protocol_change_mid_scan_...` and `protocol_change_while_idle_...` fail. With the deadline set to `Duration::MAX`, `scan_past_deadline_records_timeout` fails. With `follow_protocol = true` regardless of `uses_protocol()`, `protocol_agnostic_scanner_is_not_rescanned_on_change` fails. With `kill_on_drop(false)` in the helper, `kill_on_drop_command_sets_kill_on_drop` and `dropping_an_in_flight_scan_kills_the_ping_child` fail (the child is still `S` after the abort). With `switch_protocol` not sending, `switch_protocol_cycles_state_and_notifies_scanners` fails. All restored: 272 pass, `otto ci` green.

Live AC5 (release build, 200x55, `RUST_LOG=debug scan google.com`): `expect text "avg:"` 0; `key press p` 0; 3s wait (`expect text "zz-never-present" --timeout 3000`) 1, as expected; the last `scan::ping] scan: target=` line is `2026-10-29 14:59:05.109 [DEBUG] scan::scan::ping - [scan::ping] scan: target=google.com protocol=IPv4`; `close --all` 0. The log has `[tui] protocol_changed: IPv4+IPv6 -> IPv4 (scanners notified)` at 14:59:02.107. Within 1ms, dns, geoip, traceroute, http, port, tls and ping each logged `protocol_changed_while_idle` + `scan_cycle_starting ... protocol=IPv4`, and whois logged nothing (opted out).
