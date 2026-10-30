## Phase 1: Honest small labels

### Design decisions
- Sparkline title drops `scale 0-N` unless a successful sample is visible; `← Ns` stays. File: `src/tui/connectivity.rs` full-mode title. Why: a scale for zero replies was the fallback 1ms, not a measurement.
- One `family_state_text(state, view, visible, StateForm, checking_text)` serves full and compact rows; a Disconnected family shows `family_failure_label` in both, so compact no longer reads `v6 ---`. File: `src/tui/connectivity.rs`. Why: one function kills the class.
- Ports: the progress block and its three constants are deleted. A Running refresh draws neither `Progress:` nor `Scanned: completed` (the retained result would make `completed` a lie); the header's `↻ refreshing` carries the state. File: `src/tui/ports.rs`.
- Cert CN: the 25-char cap and `CN_DISPLAY_MAX_LENGTH` are removed; `fit_line` marks any cut with `…`. File: `src/tui/security.rs:common_name_display`.
- Security Features: `PFS: n/a` (Gray) when the handshake failed; `OCSP: not checked` (Gray) always, so the `ocsp` field was dropped from the pane's data extraction. File: `src/tui/security.rs`. Why: stapling is never collected.
- User labels: `CspStrength::label`, `CorsSecurityLevel::label`, `PrivacyLevel::label` beside their enums; HTTP grade uses `SecurityGrade::as_str`. The HTTP-grade color match keyed on the string `"APlus"` and now keys on `"A+"`. Files: `src/scan/http.rs`, `src/scan/whois.rs`, `src/tui/security.rs`.
- `TracerouteHop::is_silent()` (no probe answered) backs `TracerouteData::silent_hops()` and `last_reply_hop`; the TUI hop row uses `is_silent` and `pretty.rs` calls `silent_hops()`, replacing the `packet_loss > 0.5` count and its constant. Files: `src/scan/traceroute.rs`, `src/pretty.rs`, `src/tui/traceroute.rs`.
- Null MX: `is_null_mx` matches exactly one record, priority 0, exchange `.`; renders `MX: none (null MX)` in Gray. File: `src/tui/dns.rs`.
- First-render log moved into `TuiApp::run` after the first `terminal.draw`. `run` delegates to `run_with_keys(.., next_key)` so a test can inject the key source; `with_startup(Instant)` keeps `startup_to_render` measured from process start. Files: `src/tui/mod.rs`, `src/main.rs`.

### Deviations
- The doc says the TUI uses `silent_hops()`, but the TUI draws per-hop rows and has no count until Phase 7 collapses silent runs. The TUI shares the `is_silent` predicate instead (same effect, correct seam); Phase 7 can call `silent_hops()` when it adds run rows.
- The log line is now `[tui] First TUI render completed` (was `[main]`) because `TuiApp` emits it. Message text unchanged.
- Compact Connectivity uses the full failure label, not a shortened one, because the criterion needs the same text in both modes. A very narrow pane cuts it with `fit_line`.

### Tradeoffs
- Injecting the key source (`run_with_keys`) vs polling the real terminal in a test: only injection can assert "logged before any key is read".
- Dropping the `Scanned:` line during a refresh vs a new word: the header already says `↻ refreshing`; a second label repeats it.
- Test-only capture logger via `log::set_logger` in `src/tui/mod.rs`: safe while no other lib test installs a logger; it needs a guard if one ever does.

### Open questions
- None.

Evidence: each new test was run with its fix mutated away and failed (scale title, shared no-route text, ports progress, CN cap, PFS, OCSP, CSP/CORS/grade labels, privacy label, silent-hop count, null MX, first-render log); sources were then restored.

## Phase 3: Failure honesty in scanners

### Design decisions
- `status_label` matches `Running` on `(error, result)`: an error set reads `failed: <e> · ↻ retrying` (Red), before the `↻ refreshing` and first-scan cases. File: `src/tui/status.rs`. `failure_text` (used by Connectivity) is unchanged; it stays `Failed`-only.
- A TCP connect seam, `TcpConnector` (`src/scan/connect.rs`), holds the connect function for Ports and TLS. Production uses `TcpConnector::system()` (`TcpStream::connect`); tests inject `TcpConnector::failing_with(errno)` through `#[cfg(test)] with_connector`. Why: the criterion needs a fake connect returning ENETUNREACH, and a struct field is the narrowest seam that both scanners share.
- Ports: `scan_port` returns a `PortProbe` (Open, Closed, Filtered, NoRoute) instead of `Result<Option<OpenPort>>`. `classify_connect_error` maps `ErrorKind::ConnectionRefused` to Closed, `classify_route_error` `NoRoute` to NoRoute, everything else (EHOSTUNREACH included) and a connect timeout to Filtered. One NoRoute probe fails the family with `RouteError::NoRoute`, so no port count is reported for it. File: `src/scan/port.rs`.
- TLS: a phase-1 connect or handshake error now returns `Err` from `perform_tls_scan_for_ip`; `classify_tls_error(error, family)` runs the `{:#}` cause chain through `classify_route_error`. Certificate rejection still takes the `Rejected` path and its F. File: `src/scan/tls.rs`.
- GeoIP: `AddressKind::of(ip)` classifies loopback, private, link-local, documentation (IPv4 and 2001:db8::/32), CGNAT 100.64/10 and unique-local, after `to_canonical()` so an IPv4-mapped address counts as its IPv4 form. `GeoIpService::lookup_ip` returns the typed error `NotGeolocatable(kind)` before the cache or any request, and `lookup_ipinfo` returns `NotGeolocatable(Bogon)` for `"bogon": true`; that error is passed through unwrapped so `family_outcome` can downcast it. `GeoIpStatus::NotGeolocatable(AddressKind)` is an answer: the scan returns `Ok` when any family is Success or NotGeolocatable. File: `src/scan/geoip.rs`.
- The three duplicated GeoIP per-family error blocks collapsed into `family_outcome`; a `Failed` reason now carries the `{:#}` cause chain.
- GeoIP pane: a result with no located family and a `NotGeolocatable` family shows header `not geolocatable` and `📍 Location: not geolocatable (<kind> address)`, both Gray. `--no-tui` prints the same label as NotApplicable (⚫). Files: `src/tui/geoip.rs`, `src/pretty.rs`.
- Port, TLS and GeoIP each gain `failure_summary(protocol)` over `family_failure_summary`, replacing `All port scan attempts failed ...`, `All TLS attempts failed ...` and the `{:?}` GeoIP aggregate.
- `ipinfo` and `ip-api` base URLs are fields on `GeoIpService` (`with_base_urls` in tests) so a local `FakeHttp` can count requests; `FakeHttp` gained `total_hits()` and `base_url()`.

### Deviations
- MUTED is rendered as `Color::Gray` (the color existing muted text uses), not a theme constant: Phase 2 (`theme.rs`) has not run yet. The `failed: … · ↻ retrying` label is `Color::Red` for the same reason. Phase 2 migrates both.
- Unique-local and IPv6 link-local use std `Ipv6Addr::is_unique_local` / `is_unicast_link_local` (stable since Rust 1.84), not hand-rolled as the doc says; CGNAT and 2001:db8::/32 are hand-rolled as specified.
- The doc says EHOSTUNREACH "and others" count as filtered; a connect timeout, previously a filtered `Err`, stays filtered.
- Bogon kind label is `reserved` (`not geolocatable (reserved address)`), since ipinfo does not say which range.
- `pretty.rs` test `tls_connection_failure_prints_failure_icon_and_reason` pinned the old behavior (a connect error as a TlsData with `Connection failed: …, grade F`). That state can no longer be produced, so it was replaced by `tls_connection_failure_prints_reason_and_no_grade`, which formats the scanner error and asserts no grade.
- The ENETUNREACH tests are `#[cfg(target_os = "linux")]` because they build the error from errno 101 (macOS numbers it 51).

### Tradeoffs
- Any NoRoute probe fails the Ports family vs requiring all probes to agree: a missing route is a host property, so one probe proves it; a route flapping mid-scan is not worth a mixed verdict.
- Local classification inside `GeoIpService::lookup_ip` vs only in the scanner: the service is the single chokepoint, so any future caller also makes zero requests for a local address.
- A typed `NotGeolocatable` error downcast vs a new return enum from `lookup_ip`: keeps the public `lookup_ip` signature and `lookup_multiple_ips` unchanged.

### Open questions
- None.

Evidence: each new test was run with its fix undone and failed (status_label retrying, Ports NoRoute counted closed, TLS connect error returned as graded `Ok`, GeoIP local classification removed (the fake server then saw requests), ipinfo `bogon` ignored, GeoIP pane label and header, `--no-tui` NotApplicable); sources were then restored and `otto ci` re-run green.
