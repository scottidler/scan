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

## Phase 6: Generic content, scroll and overflow

### Design decisions
- `Detail::{Normal, Zoomed}` and the `Pane` methods live in `src/tui/pane.rs`. `content(state, width, detail) -> Vec<Line<'static>>` is required. `render` has a default that draws the content rows at offset 0, and `render_detail` defaults to `render`. A new `scrolls()` defaults to true. Connectivity returns false and overrides `render` (sparklines). Why: the layout needs a signal for which panes it scrolls, and that pane is the only exemption.
- `draw_rows(pane, frame, area, state, focused, detail, offset) -> u16` (`src/tui/pane.rs`) is the one renderer. It draws the block, calls `content` at the inner width, clamps the offset through `RowView::new(total, visible, offset)`, writes `RowView::marker()` (`↓ N more`, `↑ N`, or `↑ N ↓ M more`) right-aligned on the bottom border, and draws the visible slice without wrapping. It returns the clamped offset.
- `PaneLayout` keeps `scroll: HashMap<(&'static str, Detail), u16>` and the last rendered frame `area`. `render(&mut self, ..)` stores each clamped offset back after drawing, so a resize or shorter content re-clamps on the next frame. `handle_key_event(key, state)` sizes the focused pane with the same rect function, `pane_rect(grid_rows, grid_cols, config, area)` over the free `grid_layout(area)`, and clamps there too. Up therefore steps back from the real end even after extra Downs with no frame drawn in between. `PaneLayout::detail()` returns `Normal` until Phase 8 adds `zoomed`.
- `src/tui/text.rs`: `wrap_line(line, width)` wraps word by word, breaking after the last space that fits. A word longer than a row breaks between graphemes, and a wide glyph that would straddle the edge starts the next row. Span styles, line style and alignment are kept. `to_rows(lines, width, detail, wrapped)` replaces `fit_lines_except`. Normal fits each line with `fit_line` except the `wrapped` indices (status and reason lines), which go through `wrap_line`. Zoomed wraps every line. `owned()` turns a borrowed line into `Line<'static>`.
- Each pane's `render` became `content`. WHOIS, HTTP, Ports and GeoIP keep their `wrapped` index lists. DNS, Security and Traceroute pass `&[]`, so they fit every line as before. HTTP's one-row redirect check now uses `width`.
- Connectivity: the status row moved into the free function `status_line(state, ipv4, ipv6)`. `content` returns that one row, and `render` calls the same function with its single snapshot.
- Deleted: `src/tui/scrollable.rs` (`ScrollablePane`, `calculate_content_lines`), the DNS and Security `scroll_offset`/`scroll_up`/`scroll_down_smart`/`reset_scroll`, `SecurityPane::get_actual_line_count`, Traceroute's `scroll_offset`, the downcast key routing and `pane_areas[2][2]` in `layout.rs`, `BORDER_HEIGHT_OFFSET`/`FALLBACK_VISIBLE_LINES`, `create_grid_layout_public`, and the `terminal.size()` rebuild in `mod.rs`.

### Deviations
- Target content no longer depends on height, because `content` gets no height. The old render collapsed the scanner list to a one-line summary when the list did not fit. The new order is target, IPv4, IPv6, `Status: <summary>` (the old collapsed summary, e.g. `8/8 ✅ 1 🔄`), the protocol hint, then one row per scanner. Hidden rows are marked `↓ N more`. At 80x24 (4 inner rows) the same four facts show as before. The protocol hint moved below Status, and the blank spacer row is gone. Two old tests pinned the height-based collapse: `test_short_pane_collapses_never_clips_subset` became `short_pane_shows_the_summary_and_marks_the_hidden_scanners`, and `test_tall_pane_shows_every_scanner_and_no_summary` became `tall_pane_shows_every_scanner_the_summary_and_no_marker`.
- `Pane::scrolls()` is not in the doc's API. It is how the layout tells a row pane from Connectivity. The doc's `render_detail` defaulting to `render` is kept as written.
- `Pane::render` now has a default (draw rows at offset 0), so the eight row panes no longer implement it. `testing::render_pane` goes through it, so every existing pane test now also sees the marker.
- The layout's scroll map is read by `PaneLayout::scroll_offset(id, detail)` (public, used by the tests), and the rect by `PaneLayout::pane_area(id, area)`. The doc names neither.

### Tradeoffs
- Clamping at key time and again at render vs only at render: either one alone fixes item 10 while a frame is drawn after every key. Doing both keeps the stored offset true even when several keys arrive between frames, and a test covers that case (`up_after_scrolling_to_the_end_changes_the_view_on_the_first_press` presses Down rows+5 times with no frame drawn).
- Key handling rebuilds the focused pane's content to learn its row count, vs caching the count from the last render: the rebuild costs one `content` call per key. A cached count could go stale if the scanner state changed between the frame and the key.
- The marker sits right-aligned on the bottom border, vs a content row: it costs no content row, so `content().len()` stays the true row count.

### Open questions
- None.

Evidence: each new test was run with its fix undone, and each failed. Sources were then restored and `otto ci` re-run green.
- Marker removed from `draw_rows`: `every_scrolling_pane_marks_the_rows_it_does_not_show` and the inverted Target short-pane test fail.
- `to_rows` fits the `wrapped` lines instead of wrapping them (row count = logical lines): `whois_wrapped_domain_row_counts_every_row_it_takes`, the marker test, the scroll-to-end test, the Up test, `to_rows_fits_normal_lines_and_wraps_the_listed_ones`, and two existing wrap tests fail.
- Down clamped one row short: the marker test, `scrolling_to_the_end_reveals_the_last_built_row_in_every_scrolling_pane` and the re-clamp test fail.
- Render keeps the unclamped offset (no write-back): `a_resize_or_shorter_content_reclamps_the_offset` fails.
- Item 10 as before (no write-back, unclamped Up/Down): `up_after_scrolling_to_the_end_changes_the_view_on_the_first_press` and the re-clamp test fail.

The parametrized tests cover `SCROLLING_PANES` (every pane but Connectivity). `scroll_tests_cover_every_pane_but_connectivity` checks that this list matches the layout's panes and that only Connectivity returns `scrolls() == false`.

## Phase 7: Traceroute layout

### Design decisions
- The destination has its own row: `📍 IPv4 ✓ reached` (or `✗ target silent (last reply: hop N)`), then `→ <target ip> (<rtt>)` — `src/tui/traceroute.rs` `destination_line`. The `Route:` word is gone from the header. A reached target whose answering hop cannot be found reads `→ <ip>` with no parentheses; a silent target reads `→ <ip> (no reply)`.
- `TracerouteData::destination_hop()` (`src/scan/traceroute.rs`) is the last hop with a non-timeout answer from `target_ip`, and only when `destination_reached`. That hop is left out of the hop list so the target is not printed twice.
- `hop_lines` collapses a run of silent hops (`TracerouteHop::is_silent`) to `3-9: no reply (7 hops)`, a run of one to `3: no reply`. No hop row carries the word `timeout`. Silent rows are Gray.
- Hop numbers use `HOP_NUMBER_COLOR = Color::White` (the doc's LABEL value). The local/mid/far green/yellow/red thresholds are deleted. Phase 2 should replace the constant with `theme::LABEL`.
- Duration is the last content row, not pinned. The blank spacer row under Status is dropped (as Phase 6 did for Target). At 80x24 the pane has 8 inner rows, and the tatari fixture takes exactly 8: Status, 📍, →, hops 1, 2, `3-9`, 10, Duration. The test asserts no `↓ N more` marker and that Duration is the row above the bottom border. A longer route scrolls with the Phase 6 offsets; Duration is reached at the end of the scroll, and Zoom (Phase 8) shows every row.

### Deviations
- The doc says Duration stays the last row; it does not say how it interacts with scroll. Decision above: last content row, with no pinned footer, since a footer would need new layout machinery that `content()` does not have. The 80x24 criterion holds only because the spacer row was dropped and the destination hop leaves the list; a tatari-like route with more than four answering hops would scroll Duration out of the 80x24 view (marked `↓ N more`).
- `tui_and_no_tui_report_the_same_silent_hop_count` counted `timeout` rows; it now asserts `2: no reply` and `4: no reply` rows (and no `3:`), still checking `silent_hops() == 2` and the `--no-tui` summary.
- `long_ipv6_hop_is_fit_with_ellipsis_in_narrow_terminals` now clips the destination row (`→ <ip> (5ms)`) since its fixture hop is the target and moves to that row.

### Tradeoffs
- Drop the spacer row vs pin Duration: dropping costs one blank row and no new mechanism; pinning would be robust for long routes but needs a footer concept in `Pane`.
- Match the destination hop by IP against `target_ip` vs treat the last hop as the destination when reached: matching never hides a hop that is not the target.

### Open questions
- None.

Evidence: each new test was run with its fix undone, and each failed. Collapse disabled: `tatari_route_fits_the_80x24_dashboard_with_destination_and_duration`, `a_single_silent_hop_reads_without_a_count`, `tui_and_no_tui_report_the_same_silent_hop_count`. Destination row and hop removal disabled: the tatari fit test, `a_silent_target_keeps_its_label_and_a_no_reply_destination_row`, the long-IPv6 clip test. Red hop numbers and `timeout` text restored: `hop_numbers_use_the_label_color_never_the_bad_color`, `no_hop_row_says_timeout`, and two others. Sources restored, then `otto ci` green.

## Phase 8: Zoom

### Design decisions
- `PaneLayout.zoomed: bool` drives zoom, and `detail()` returns `Zoomed` while it is set. `zoom()` (Enter) needs a focused pane, sets `zoomed`, and drops that pane's `(id, Zoomed)` offset, so every zoom starts at row 0. `unzoom()` (Esc) clears `zoomed` and leaves every grid offset alone. `set_focus` drops the newly focused pane's zoomed offset while zoomed, so Tab/Right and BackTab/Left move the zoom to a pane that starts at row 0. File: `src/tui/layout.rs`. Why `set_focus`: it is the one place focus changes, so no key path can skip the reset.
- One rect function: `PaneLayout::rect_of(id, area)` returns `zoom_rect(area)` (the frame minus a one-row footer) for the zoomed pane, `None` for the other panes while zoomed, and the grid cell otherwise. `render`, `handle_key_event` and the public `pane_area` all call it, so key-time clamping uses the zoomed rect.
- `render` draws only the focused pane at `Detail::Zoomed` (`render_zoomed`), plus the `ZOOM_FOOTER` row `Esc back · ←/→ pane · ↑/↓ scroll`. If the focused pane cannot be found, zoom is dropped with a WARN and the grid is drawn, so the screen is never blank. The per-pane draw and offset write-back moved into a free `draw_pane(pane, &mut scroll, ..)` that both paths share, so a resize while zoomed re-clamps through the same write-back as the grid.
- Key handling moved out of the event loop into `TuiApp::handle_key` (`src/tui/mod.rs`), so tests can drive keys. `q` and Ctrl-C always quit. Esc leaves zoom when zoomed and quits otherwise. Enter calls `layout.zoom()`. Everything else is as before.
- Per-pane zoom content, from already-collected data only. Each pane branches on `detail` inside `content`:
  - Traceroute (`zoomed_route_lines`): both families. Each family shows its header and destination row, then every hop with no collapsing and the destination hop included: each probe's `ip rtt` or `*`, and the hop's loss computed from its probes. A family with no data reads `📍 IPv6: <status>`. Duration closes the pane.
  - DNS: `record_line` adds each record's own `TTL:` when zoomed. TXT verification tokens (`google-site-verification`, `MS=`) are abbreviated only in the grid. SOA adds Email, Refresh, Retry, Expire and Minimum TTL.
  - Security: the list caps (CSP issues, CORS issues, HTTP and TLS vulnerabilities) lift when zoomed, and CORS methods are listed by name. `zoomed_tls_lines` then appends supported versions and the full certificate chain: subject, issuer, serial, validity, signature, key and SANs for each certificate. Email security (SPF, and DMARC with its full text) was already in the pane and now wraps whole.
  - HTTP (`zoomed_lines`): URL, pinned IP, every security header with its value (`missing` when absent), the CSP header, CORS allow-origin/methods/headers/credentials, and the four caching headers. The redirect chain and vulnerabilities were already listed in full.
  - WHOIS (`zoomed_lines`): last updated, DNSSEC, age, registrar IANA ID and URL, the registrar's abuse contact, and the registrant, admin, tech and abuse contacts (`(redacted)` when withheld).
  - Ports: no 5-port cap; under each port, `service_detail_lines` adds version, banner and connect time.
  - GeoIP (`zoomed_lines`): each family's IP, city, region and country with codes, coordinates, timezone, ISP, organization, ASN, AS name, network range, source and lookup time, or the family's status.
  - Target: unchanged.
- Connectivity overrides `render_detail`, and `render` now delegates to it at `Normal`. Zoomed, the graphs fill the frame (taller sparklines), and each family title adds `loss N% · jitter Xms` over every kept sample (`SparklineData::all`, up to 200), not only the visible ones. `loss_percent` rounds. `jitter_us` is the mean absolute difference between consecutive cycles that both got a reply, and a failed cycle breaks the pair. Both live in `src/tui/sparkline.rs`.
- Traceroute hop loss rounds the same way (`1 answer in 3` reads `67%`), so the two loss figures agree.
- Test helper `testing::content_rows(pane, state, width, detail)`.
- New color literals for Phase 2 to migrate: the zoom footer (Gray, MUTED); the zoomed field labels/values in `http.rs` (`header_line`, White/Gray, `missing` Yellow), `whois.rs` (`field_line`, `contact_lines` Cyan header), `geoip.rs` (`field_line`, `status_text`: Green/Red/Gray), `ports.rs` (`service_detail_lines`), `security.rs` (`zoomed_tls_lines`) and `traceroute.rs` (`every_hop_lines` Cyan/Gray, the zoomed family-status line Red/Gray); the Connectivity loss/jitter span (Gray).

### Deviations
- The doc puts the full certificate chain under Security's certificate details. It is appended after Email Security instead, so zoom keeps the grid's section order and `DMARC: configured` stays on the first screen at 200x55 (AC5). Verified on a release build against google.com: the chain starts below DMARC.
- `PaneLayout::pane_area` now returns the zoom rect for the zoomed pane and `None` for the other panes while zoomed. It used to always return the grid cell. All existing callers run unzoomed.
- `Pane::render` on Connectivity now delegates to `render_detail(.., Normal)`. The doc has `render_detail` default to `render`; that default is unchanged, and only the override direction is reversed for the one pane that overrides it.
- HTTP zoom shows no per-family status line: `HttpStatus` has no `Display`, and adding one is outside this phase. The primary result's fields are shown.
- AC4 as written (`tui-test ... key press BackTab`) cannot pass with this tui-test: its verbose log shows `WRITE BackTab` (the literal text) while Enter logs `WRITE \r`. `key press shift+tab` writes `\e[Z` and AC4 then passes on a release build of this commit (SECURITY hidden, TRACEROUTE shown, Escape back to the grid with SECURITY). Phase 8's code is correct; the AC's key name needs changing.

### Tradeoffs
- Resetting the zoom offset on every focus change vs keeping a per-pane zoom offset across visits: the doc asks for 0 on Left/Right. One rule (zooming into a pane starts at its top) is easier to predict than a remembered position.
- Zoom extras appended after the grid content vs reordered for zoom: appending keeps the order a user already knows from the grid, at the cost of the most detailed data sitting lowest.
- Jitter as the mean consecutive difference vs RFC 3550's smoothed estimator: the mean over a fixed window is reproducible from the samples shown and is testable exactly. The smoothed estimator weights recent samples, which the window already does.
- Footer only while zoomed vs always: the grid has no footer today. Adding one would take a row from every 80x24 pane and break the Phase 7 fit.

### Open questions
- AC4's key name: change `key press BackTab` to `key press shift+tab` in the doc's Acceptance Criteria? The command as written types the text `BackTab`.

Evidence: each new test was run with its fix undone, and each failed. Sources were then restored byte-for-byte and `otto ci` re-run green. The undone fixes:
- render ignores `zoomed`: `zoom_draws_exactly_one_pane_title_and_the_key_footer` fails.
- no zoom-offset reset in `set_focus`: `right_while_zoomed_shows_the_next_pane_from_its_first_row` fails.
- no zoomed offset write-back: `a_resize_while_zoomed_stays_zoomed_and_reclamps` fails.
- Esc always quits: `esc_while_zoomed_leaves_zoom_and_does_not_quit` fails. Esc never quits: `esc_while_not_zoomed_quits_and_q_quits_from_zoom` fails.
- `detail()` always Normal: `grid_and_zoomed_offsets_of_one_pane_are_independent` fails.
- traceroute zoom branch off: `zoomed_content_shows_every_probe_rtt_for_a_hop` fails. Floor instead of round: `zoomed_hop_loss_is_rounded_like_connectivity` fails.
- `to_rows` fitting at Zoomed, and TXT abbreviated at every detail: `zoomed_content_shows_a_300_char_txt_record_in_full_wrapped` fails for each.
- per-record TTL off: `zoomed_content_gives_each_record_its_ttl_and_every_soa_field` fails.
- Security chain off: `zoomed_content_lists_the_certificate_chain_and_dmarc_in_full` fails. Caps kept: `zoomed_content_lists_every_tls_issue_past_the_grid_cap` fails.
- HTTP, WHOIS, GeoIP and Ports zoom off: their `zoomed_content_*` tests fail.
- Connectivity loss/jitter off: `zoomed_render_adds_loss_and_jitter_over_every_sample` fails.

Live, release build of this commit, 200x55: AC5 `google.com` Enter shows `DMARC: configured`. The same text was not visible in the grid within 45s, so the check is meaningful. AC4 passes with `shift+tab` as above, and a second Escape exits 0.

## Orchestrator: AC4 amendment (doc defect)

- AC4 named `key press BackTab`. tui-test has no BackTab key name and types it as literal text. Evidence, `tui-test run -- cat -v` then `key press BackTab Enter shift+tab Enter`: `expect text "BackTab"` exits 0, `expect text '^[[Z'` exits 0. The criterion's intent (Shift-Tab from Security to Traceroute) is unchanged; only the key name is fixed to `shift+tab`. The main-branch observation (1, 0, 1) never exercised the key: its middle check passes on main regardless.

## Phase 0: Glyph width check (operator step)

- Scott ran `printf 'xx|\n⏳|\n❗|\n🧭|\n🔰|\n🏦|\n💻|\n'` on ripr on 2026-10-29 and sent a screenshot. Every glyph row's `|` lines up with the `xx|` ruler, so all six glyphs are 2 cells in his terminal. Phase 2 uses the full replacement set; no glyph is dropped.

## Phase 2: Theme and glyphs
### Design decisions
- `src/tui/theme.rs` holds `BAD` (LightRed, ANSI 9), `WARN`, `GOOD`, `VALUE`, `LABEL`, `MUTED`, `ACCENT` (Magenta), `BORDER_FOCUSED`, `BORDER_UNFOCUSED`; `create_block` in `src/tui/pane.rs` reads the borders from it. Every `Color::` in non-test code under `src/tui` migrated, including the stand-ins Phases 3, 4, 5, 7 and 8 left (MUTED/GOOD in connectivity, `ttl_span` expired, DKIM line, `HOP_NUMBER_COLOR`, zoom footer and zoomed field lines).
- Lint is `theme::tests::no_color_literal_outside_theme_and_test_modules` (reads every `src/tui/*.rs`, stops at the first `#[cfg(test)]`, skips `//` lines) with a companion `the_color_lint_catches_a_color_added_to_a_pane` that exercises the detector on a synthetic source, so the lint itself cannot rot.
- Glyphs: all six VS16 emoji replaced with the confirmed 2-cell set. `no_pane_source_contains_a_variation_selector` scans sources; `rendered_traceroute_pane_has_no_variation_selector` checks a rendered pane.
- Reclassifications: hop number LABEL; TTL <=60s WARN (>60s GOOD, never BAD; expired MUTED); MX priority LABEL (thresholds deleted); `Privacy: Open` VALUE; EPP `ok` and `* prohibited` locks GOOD via `whois::is_lock_or_ok`; HTTP time >=500ms WARN (<500ms GOOD, the 100ms tier deleted); HTTP 5xx BAD (was ACCENT); open ports 0 GOOD, 1-5 LABEL, >5 WARN.
- Verified bites (fix undone, test fails, restored): lint with `Color::Red` in `pane.rs`; U+FE0F re-added in `traceroute.rs` (source and rendered); `prohibited` dropped from `is_lock_or_ok`; `BAD` set to `Color::Red` (six tests fail, including the failed ping label).
- AC6 equivalent in tests: `client transfer prohibited` renders `Color::Green` (ANSI 2) and `no echo reply` renders `Color::LightRed` (ANSI 9).

### Deviations
- Open ports 1-5 is LABEL, not WARN: the doc only says >5 is WARN, and keeping 1-5 WARN would make both tiers identical. Same effect on the doc's intent.
- HTTP 3xx stays WARN and 4xx stays BAD; the doc did not reclassify them.
- Unknown EPP statuses (for example `serverHold`) stay BAD; `pending*` stays WARN.
- `ACCENT` is Magenta; the doc names no value.
- AC6 itself (live `expect text --fg`) not run here; covered by the unit tests above.

### Tradeoffs
- Source-scanning lint vs a clippy `disallowed` rule: the scan needs no config and its failure message lists file:line.
- Mechanical per-color mapping then hand reclassification vs hand-editing 500 sites: fewer typos, and the test suite pinned the result.

### Open questions
- Should `ACCENT` be Magenta or something else on Scott's palette?
- Should open ports 1-5 stay neutral LABEL?
