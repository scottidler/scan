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

## Phase 4: Protocol and no-address state

### Design decisions
- Protocol reset at scan start: `Scanner::run` keeps `last_protocol: Option<Protocol>` local to the loop. Each scan start compares it to the protocol `borrow_and_update()` returned, and for a `uses_protocol()` scanner a difference calls `clear_for_protocol_change` (result, error and history cleared, debug log) before `mark_running`. File: `src/scanner.rs`. Why: the check runs at scan start, so it does not matter which `select!` branch woke the loop, and it also covers a scan cancelled mid-flight and restarted. WHOIS (`uses_protocol() == false`) never resets. An ordinary refresh still keeps its result.
- Connectivity state is per family (`FamilyHistory`: results window, state, sparkline samples). `PingStatus::NoAddress` sets `ConnectivityState::NoAddress` directly and clears the results window, and is never counted as an attempt; `was_attempted` is no longer read by Connectivity. `Disabled` is the protocol-off state. File: `src/tui/connectivity.rs`.
- `overall_status(ipv4, ipv6)` is pulled out of `render`. A family that is `NoAddress` or `Disabled` drops out, and the other family alone sets the status: Connected `ipv4`/`ipv6` (Green), Intermittent, Disconnected `no ping reply`, Checking. With both families absent the status is `no address` (Gray).
- Family-state text, shared by full and compact rows, gains `no IPv6 address` / `no IPv4 address` and `disabled (p)`. Both draw in Gray, and the title color is now derived from the state rather than a `connected` bool.
- Ingestion is out of `render`. `Pane::ingest(&self, &AppState)` is a default no-op hook, `PaneLayout::ingest` calls it on every pane, and `TuiApp::run_with_keys` calls `TuiApp::ingest` at the top of every loop iteration, before drawing. `ConnectivityPane::ingest` follows the protocol selection, then takes in the ping scanner's `history` and then its `result`, deduplicated by `queried_at`. Why history: a result published between two ticks is still counted, up to ping's history depth of 10.
- On a protocol change, `Ingested::follow_protocol` clears and disables each family the selection leaves out. A family that comes back starts over at `Checking`. A disabled family ignores any status a result carries for it.
- The pane's four mutexes (two sparklines, last timestamp, history) are now one `Mutex<Ingested>`, snapshotted once per render. The never-read `last_state_change` field is gone.
- Test helpers: `testing::render_buffer` and `testing::fg_of` (styled-buffer color lookup), `PaneLayout::pane_mut` (cfg(test)), and `ConnectivityPane::sample_counts` (cfg(test)).

### Deviations
- MUTED is `Color::Gray` and GOOD is `Color::Green`, because Phase 2 (`theme.rs`) has not run. The literals sit in `FamilyView::title_color`, `overall_status` and `single_family_status`; Phase 2 migrates them.
- The doc says "a per-tick `TuiApp` step". It is implemented as a `Pane::ingest` hook driven by `TuiApp::ingest` through `PaneLayout::ingest`. Same effect, correct seam: the layout owns the panes, and a later pane can keep history the same way.
- The doc names only `(Connected, NoAddress)`. `Disabled` is treated the same in the status matrix (`(Connected, Disabled)` reads `ipv4`, Green), and both families absent reads `no address` (Gray). The doc does not specify either case.
- Race test staging: `tokio::time::advance` cannot make both branches ready in one poll, because the `send` wakes the scanner before the driver fires the tick. The test therefore uses a `RaceStub` whose first scan overruns its 1s interval and sends the protocol change as it finishes, so the overdue tick and the change are ready together. `select!` picks at random, so the test runs 64 trials and asserts the tick branch won at least once. The winner is read from the third scan's start time: 2 x interval when the tick won, first scan + interval when the change won.

### Tradeoffs
- Reading the ping history in `ingest` vs only the current result: history makes the sample count independent of tick timing (up to 10 results between ticks). The cost is walking at most 10 entries per tick.
- Repeated randomized trials vs `biased;` on the production `select!`: `biased;` would make the test deterministic but would change production branch order only for a test. Trials leave production untouched. The tick-won assertion can miss with probability 2^-64. The reset assertion never flakes, because the fix resets on either branch.
- Clearing the results window on `NoAddress` vs keeping it: a family that later gets an address starts at `Checking`, not at a stale verdict.

### Open questions
- None.

Evidence, each new test run with its fix undone, then sources restored and `otto ci` re-run green:
- No reset at all: the idle-change test and the both-ready test fail.
- Reset done only in the idle protocol-change branch: only the both-ready test fails, at its `retained` assertion, so the tick branch did win.
- `uses_protocol()` gate removed: the WHOIS-like test fails.
- `PaneLayout::ingest` made a no-op (no ingestion without a render): both sample-count tests fail.
- Ingesting only `result`: the between-ticks test fails.
- `NoAddress` counted as a failed attempt: both five-cycle no-address tests fail.
- Status matrix warning for a missing family: the matrix test and both five-cycle tests fail.
- Disabling without clearing samples: the disabled-family test fails.
- `NoAddress`/`Disabled` titles in red: the MUTED color assertions fail.

## Phase 5: DNS collection and TTL cadence

### Design decisions
- PSL extraction: `src/scan/psl.rs` holds `SuffixList { client, url, cache_dir, fetch_timeout }` with `registrable_domain(&self, host, deadline)` and `parse_suffix_list`, moved verbatim from `WhoisScanner`. Same cache file (`public_suffix_list.dat`), same ICANN-only rule, same stale-cache fallback. WHOIS builds its `SuffixList` from its own `psl_url`, `cache_dir` and `source_fetch_timeout` (`WhoisScanner::suffix_list`), so the suffix list and the RDAP bootstrap still share one cache dir and every WHOIS test fixture keeps working unchanged.
- The fetch-and-cache module moved from `src/scan/whois/cache.rs` to `src/scan/cache.rs` (git rename), because both PSL users need it and a module private to WHOIS would make DNS reach into another scanner. `default_cache_dir()` (`~/.cache/scan`) moved with it. Log prefix is now `[scan::cache]`.
- DMARC: `DnsScanner::lookup_dmarc` asks TXT at `_dmarc.<host>`, then at `_dmarc.<registrable domain>` when that name differs (`dmarc_names`). The first answer holding a `v=DMARC1` record wins. A suffix-list failure or timeout logs a WARN and asks the host only. `analyze_email_security` is now a pure function of (apex TXT, MX, `_dmarc.` answer). SPF still comes from the apex, and DMARC comes only from the `_dmarc.` answer, so an apex `v=DMARC1` string no longer counts. Debug logs: `dmarc_found: host=… answered_by=_dmarc.…` or `dmarc_not_found: asked=[…]`.
- DKIM: `EmailSecurityAnalysis::dkim_domains` is deleted along with the invented selector loop. The Security pane always shows `DKIM: not checked (needs selector)` in Gray (MUTED) and has no DKIM detail row.
- CNAME and CAA: `DnsScanner::timed_lookup(resolver, name, RecordType)` wraps `resolver.lookup` in the per-query 5s timeout. It maps no-records and NXDOMAIN to an empty answer, a resolver error to `Failed`, and an elapsed timer to `Timeout`. `lookup_cname` and `lookup_caa` fill `CNAME`/`CNAME_status` and `CAA`/`CAA_status`. The CAA value comes from `CAA::raw_value()` (the zone-file value); `CAA::value()` is deprecated in hickory 0.25. `_dmarc.` TXT goes through the same helper.
- DNS pane: an existing CNAME or CAA section shows when records exist. A `Failed` or `Timeout` status shows `CNAME: Timeout` / `CAA: Failed`, and an empty answer shows nothing, since most names have no CNAME. A new `PTR:` section (status, TTL, records) leads the pane when `DnsResult::is_reverse_only()` (no forward lookup ran: an IP target) and comes last for a name target.
- TTL cadence: `Scanner::next_delay(&self, &ScanResult) -> Option<Duration>` defaults to `None`. `Scanner::run` computes it from the `Ok` result before `record_outcome` consumes it, calls `ticker.reset_after(d)` when it is `Some`, and debug-logs `next_scan: scanner=… delay=…ms (from result)` or `interval schedule`. A failed scan has no result, so the ticker keeps its schedule. `DnsScanner::next_delay` returns `DnsResult::requery_delay(Instant::now())`: the earliest `DnsRecord::expires_at()` (`queried_at + ttl`) across all ten record sets, clamped to 10s..60s, or `None` with no records. The injected-`now` tests call `requery_delay` directly.
- TTL display: one `ttl_span(ttl)` serves every section. It renders `<n>s (cached)` with the old threshold colors, or `expired, refreshing` in Gray (MUTED) at 0. Section headers read `NS: 2 records, TTL: 59s (cached)` (was `(TTL: 59s)`), which avoids nested parentheses.
- Gray (MUTED) sites for Phase 2 to migrate: `src/tui/dns.rs` `ttl_span` (expired), `src/tui/security.rs` DKIM line. The remaining new colors reuse existing literals (`status_display`, which was the old `get_status_display` closure, and Cyan for PTR values).

### Deviations
- The doc's `registrable_domain(&self, host, deadline: Instant)` lives on a `SuffixList` struct in `psl.rs` (the doc names no type). The `deadline` is `tokio::time::Instant`, as it was in WHOIS. Same effect, correct seam.
- The doc does not mention moving `whois/cache.rs` to `src/scan/cache.rs`. The move was needed so that `psl.rs` does not depend on a module private to WHOIS.
- An IP target is detected from the result (`is_reverse_only`, i.e. MX not attempted) rather than a new `DnsResult` field, which the Data Model does not list.
- The PSL tests (`registrable_domain_is_the_icann_registrable_domain`, `host_without_a_registrable_domain_has_none`, both corrupt-list tests, `fetched_suffix_list_without_an_icann_section_is_not_cached`) moved from `whois.rs` to `psl.rs` and now run against `SuffixList`. `PSL_FIXTURE` moved too and gained `com`. The WHOIS scan-level PSL tests stay in `whois.rs`.
- Tests that pinned the old behavior: `test_email_security_analysis` and `test_email_security_analysis_edge_cases` (`src/scan/dns.rs`) and `test_dns_data_extraction` / `test_comprehensive_data_availability` (`src/tui/security.rs`) built and asserted `dkim_domains`. Those assertions were removed with the field, and `dkim_reads_not_checked_and_dmarc_reads_configured` pins the new pane text.
- The DNS network tests now use `test_scanner()`, whose suffix list points at a dead URL with no cache dir, so a test run neither fetches publicsuffix.org nor writes `~/.cache/scan`. DMARC is then asked at the host only. `google_dmarc_is_found_at_dmarc` is a new live test (google.com is its own registrable domain).

### Tradeoffs
- Each new lookup gets its own 5s timeout (CNAME, CAA, up to two `_dmarc.` TXT, and the PSL load), per the Risks row. On a resolver that is slow everywhere this can add up past the unchanged 30s DNS deadline. The doc accepted that risk; the deadline was not raised.
- `requery_delay` takes the earliest expiry across every record type, PTR and SOA included, rather than A/AAAA only. A short-TTL TXT therefore drives the cadence too, which keeps every displayed TTL from sitting at 0 for long. The cost is a re-query at most every 10s.
- An empty CNAME/CAA answer is hidden rather than shown as `No Records`, since most names have neither. A failure is shown, so a missing section always means "asked, none".

### Open questions
- None.

Evidence: each new test was run with its fix undone, and each failed. The undone fixes: `ticker.reset_after` removed (the paused-time test then saw the second scan at 60s), the 10s..60s clamp removed, DMARC read from apex TXT instead of the `_dmarc.` answer, the organizational fallback name dropped, the `expired, refreshing` branch and the `(cached)` suffix removed, PTR-first disabled, `is_reverse_only` forced false, the CNAME failure line removed, and the old DKIM text restored. Sources were then restored and `otto ci` re-run green. CNAME/CAA collection has no hermetic test (no resolver fake). A live `scan --no-tui www.tatari.tv` run logged `cname_status=Success(1) caa_status=Success(4)`, `dmarc_found: host=www.tatari.tv answered_by=_dmarc.tatari.tv`, and `next_scan: scanner=dns delay=10000ms (from result)`.
