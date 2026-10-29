## Phase 1: Small fixes
### Design decisions
- 8080 maps to `http-alt` - src/scan/port.rs:get_service_name - matches the existing `https-alt` label for 8443.
- The failed-scan "Status:" duplicates are deleted, not reworded - src/tui/http.rs, src/tui/traceroute.rs, src/tui/ports.rs - the header already carries `failed: <reason>`. The Ports and Traceroute match arms become empty (`vec![]` / `{}`) rather than falling through to the "waiting" arm, which would add a second Status line.
- IPv6 ping guard is ping-local - src/scan/ping.rs:ping_protocol - bails with the existing "No IPv6 address available" message before `network_target_for_protocol`, so `classify_ping_error` yields `NoAddress`. target.rs is untouched.
- Tests: `service_name_labels_http_alt_and_leaves_others_unknown` (port.rs), `failed_http_traceroute_and_ports_panes_show_status_once` (tui/testing.rs), `ipv6_ping_without_aaaa_is_no_address_and_spawns_nothing` (ping.rs, uses a fake ping script that touches a marker file).

### Deviations
- None.

### Tradeoffs
- The guard keys on "no resolved IPv6 address" rather than "domain that resolved but has no AAAA", so an IPv6 ping on a not-yet-resolved domain is also `NoAddress` - simpler, and an unresolved target has no known AAAA to ping.

### Open questions
- None.

## Phase 2: WHOIS failure is an error
### Design decisions
- `scan_whois` returns `Err("RDAP: <e>; WHOIS: <e>")` on total failure - src/scan/whois.rs:scan_whois - `record_outcome` then sets `Failed`, keeps the last good result, and `status_label`/`failure_text` drive the pane header with no WHOIS-specific code.
- `DataSource::Failed` and `RiskIndicator::QueryFailed` deleted, with their arms in src/tui/whois.rs, src/pretty.rs and the `Display` impl - a failure is no longer representable as a result, so nothing can print "retrieved" over it.
- The old pretty test `whois_failed_lookup_prints_failure_icon_and_reason` is removed (it pinned the deleted variant); the generic failed-state path is covered by the new end-to-end test.
- New test `total_failure_is_an_error_the_pane_and_no_tui_output_report` uses a refusing proxy for RDAP and a bounded local IANA fake with no referral for WHOIS (every accept and read has a timeout).

### Deviations
- `scanner::record_outcome` widened from private to `pub(crate)` - the criterion needs the state transition the scan loop performs, and `run` loops forever; same effect, correct seam.
- `test_whois_scanner_timeout` now asserts `data_source != NotApplicable` on the Ok branch (its `Failed` match arm no longer exists).

### Tradeoffs
- Reusing `record_outcome` in the test vs. hand-building a `Failed` `ScanState` - the former proves the wiring, the latter would only prove the render.

### Open questions
- None.

## Phase 3: Route classifier and failure reasons
### Design decisions
- `Family { Ipv4, Ipv6 }` added beside `RouteError` - src/scan/mod.rs - the doc's signature names a `Family` type that did not exist; `Protocol` carries `Both`, which no single failure can have.
- `classify_route_error` matches the errno as Rust prints it (`(os error N)`) or the strerror text as the C tools print it - src/scan/mod.rs:mentions_errno - `traceroute6` and `ping -6` on this host print `connect: Cannot assign requested address` with no errno number, so an errno-only match would miss the defect #9 fixture.
- One aggregate helper, `family_failure_summary`, used by both `HttpResult::failure_summary` and `TracerouteResult::failure_summary` - src/scan/mod.rs - sibling scanners word failures identically. `NoAddress` families are left out for HTTP as well as traceroute; when no family was attempted the message is `no <protocol> address for target`.
- HTTP classifies `root_cause(error)` per family - src/scan/http.rs:classify_http_error - for a domain target whose HTTPS and plain-HTTP attempts both fail, the root cause is the existing `HTTPS failed: ...; plain HTTP failed: ...` message, which the classifier still reads for errno text.
- The four copied error-to-status blocks in `TracerouteScanner::scan` collapse into `family_outcome` - src/scan/traceroute.rs - one place classifies, and the failure text is `{e:#}` so a spawn error keeps its cause.
- Ping's stderr check and `classify_ping_error` go through the classifier - src/scan/ping.rs - #9 cites the `Network is unreachable`-only match; 113 (`No route to host`) now reads `host unreachable` instead of `Network unreachable`. The `PingFailure` enum and the pane labels stay with Phase 4.
- Tests: `classify_route_error_maps_each_errno_by_family`, `classify_route_error_reads_tool_strerror_without_errno`, `route_error_display_never_blames_this_host_for_113`, `family_failure_summary_joins_families_and_names_the_empty_case` (scan/mod.rs); `classify_http_error_keeps_the_root_cause_per_family`, `failure_summary_names_each_attempted_family_and_skips_no_address`, `timed_out_scan_renders_operation_timed_out_in_the_pane` (scan/http.rs, local accept-and-hold listener, 300ms client timeout, accept bounded at 10s); `status_display_has_no_debug_text`, `failure_summary_leaves_out_no_address_families`, `ipv6_literal_no_route_renders_the_route_not_debug_text` (scan/traceroute.rs); `failure_reason_prefers_an_attempted_family_over_no_address`, `classify_ping_error_names_the_missing_ipv6_route` (scan/ping.rs).

### Deviations
- The HTTP and traceroute aggregates drop their `All HTTP attempts failed for target` / `All traceroute protocols failed:` prefixes - the doc gives the aggregate as `IPv4: operation timed out; IPv6: no IPv6 route on this host`, and the pane header already says `failed:`.
- The traceroute no-route render test builds its fixture through `family_outcome` with the stderr captured on this host, not by spawning `traceroute6` - the scanner has no program override until Phase 5's fake runner; same classifier and summary path, without the process.
- `Family::from_protocol` and `Display for Family` added - not in the doc's API, needed to map the scanners' `Protocol` arguments and to print `IPv4`/`IPv6`.

### Tradeoffs
- Matching strerror text as well as the errno number vs. errno only - the tools that hit defect #9 print no number; the strings matched are the fixed glibc strerror texts.
- One shared summary helper vs. per-scanner formatting - one wording for every sibling, at the cost of the scanner name no longer appearing in the message (the pane title already names it).

### Open questions
- None.

## Phase 4: Honest ping labels
### Design decisions
- `PingStatus::Failed(PingFailure)` with `NoReply | NoRoute | Other(String)` - src/scan/ping.rs - classification happens where ping output is read, so the TUI never string-matches.
- A silent non-zero ping exit raises a private typed error `NoEchoReply`; `classify_ping_error` finds it with `chain()` - src/scan/ping.rs:do_ping, classify_ping_error - a type, not a "no reply from" substring match.
- `NoRoute` is recovered by downcasting the `RouteError` the ping path already bails with, and by `classify_route_error` on text; no errno matching duplicated - src/scan/ping.rs:classify_ping_error.
- `PingFailure::label(family)` renders `no echo reply`, `no IPv6 route on this host` (via `RouteError::Display`), or the raw reason; `failure_reason()` uses it, so `--no-tui` ("Ping failed: no echo reply") and the TUI agree - src/scan/ping.rs, src/pretty.rs.
- Per-family disconnected line shows that family's latest failure label (`family_failure_label`), replacing the hard-coded IPv4 "disconnected" and IPv6 "network unreachable" - src/tui/connectivity.rs.
- Overall status `no ping reply`; the `: <reason>` suffix is appended only when the reason is not already `no echo reply` - src/tui/connectivity.rs.
### Deviations
- `NoRoute` is a unit variant as specified, so the family comes from which status slot holds it (`label(family)`), not from the variant.
- One extra downcast branch the spec did not mention: the typed `RouteError` bailed in `do_ping` loses its type once flattened to text, so `classify_ping_error` downcasts before falling back to text.
### Tradeoffs
- Typed `NoEchoReply` error vs matching the message text: survives message rewording.
- Per-family label read from the latest ping result vs storing the failure in the smoothed history: the history holds only booleans, and the label should describe the latest sample.
### Open questions
- None.

## Phase 5: Traceroute over ICMP
### Design decisions
- `traceroute_args` is a pure function returning program and arguments, modeled on `ping_args` - src/scan/traceroute.rs:traceroute_args - `-I` is added only when `use_icmp` is set and the OS is `linux` or `macos`, the two platforms the doc names; elsewhere the UDP default stands, which is what `target_os` decides.
- One run is split into `run_traceroute(target, ip, use_icmp)`; `perform_traceroute_for_ip` runs ICMP and, only when the error text contains the privilege refusal (`icmp_refused`), runs UDP once - src/scan/traceroute.rs - a silent target exits 0 with `*` hops, so it is a result, never an error, and cannot reach the retry branch.
- Injectable program: `program_override: Option<String>` plus `with_program`, the same seam `PingScanner` uses - src/scan/traceroute.rs:TracerouteScanner - lets tests run a fake script through the production spawn path.
- `TracerouteData::last_reply_hop` and `reach_label` own the wording (`reached`, `target silent (last reply: hop N)`, `target silent (no hop replied)`); the pane prepends `✓`/`✗` and `--no-tui` uses the same label - src/scan/traceroute.rs, src/tui/traceroute.rs, src/pretty.rs - one wording for both outputs; `✓ reached` is unchanged for AC1.
- The fake script is written by a child `sh`, not `std::fs::write` - src/scan/traceroute.rs:tests::fake_traceroute - when this process holds the write fd, a sibling test's fork inherits it and exec of the script fails with `Text file busy (os error 26)`; reproduced 4 times in 25 `cargo test --lib` runs before the change, 0 in 40 after.
- Tests: `traceroute_args_use_icmp_on_linux_and_macos`, `traceroute_args_without_icmp_or_on_other_platforms_use_udp`, `icmp_refused_matches_only_the_privilege_text`, `icmp_privilege_refusal_retries_exactly_once_over_udp`, `other_icmp_failure_is_not_retried`, `silent_icmp_target_is_not_retried`, `reach_label_names_the_last_replying_hop`, `silent_target_renders_target_silent_with_the_last_reply_hop`, `reached_target_renders_check_reached` (scan/traceroute.rs). Each was shown failing with its fix undone.
### Deviations
- `--no-tui` (src/pretty.rs) also prints the `target silent (...)` label instead of `unreached`. The doc names only the pane; one shared label keeps the two outputs from disagreeing.
- The "fake runner" is a fake program behind `with_program`, not a runner trait. Same check (counts runs and their flags), same seam as `PingScanner`.
### Tradeoffs
- Retrying UDP on every scan cycle vs remembering that ICMP was refused: the refusal costs one fast failed spawn per 5-minute cycle, and remembering would add state the doc did not ask for.
- Fake script through the spawn path vs a trait object returning canned `Output`: the script also covers argument building and the stderr wiring, at the cost of being unix-only (`#[cfg(unix)]`).
### Open questions
- `src/scan/ping.rs` tests write fake scripts with `std::fs::write` and exec them, the same ETXTBSY race fixed here for traceroute. Not observed failing in this phase's runs; should it get the same child-`sh` write?

## Phase 5 amendment: shared test script writer
Supersedes the Phase 5 open question about `src/scan/ping.rs` (orchestrator ruling: fix it in this phase).
### Design decisions
- `write_executable_script(path, content)` in a `#[cfg(all(test, unix))]` module - src/scan/testing.rs - one child-`sh` writer for every test that writes then execs a script, so the ETXTBSY class is closed rather than one instance.
- Callers: `fake_traceroute` (src/scan/traceroute.rs), `ipv6_ping_without_aaaa_is_no_address_and_spawns_nothing` and `dropping_an_in_flight_scan_kills_the_ping_child` (src/scan/ping.rs). `rg` for `fs::write`, `set_permissions` and `from_mode` under src/ finds no other write-then-exec test.
- The no-AAAA ping test asserts the script was NOT spawned, so ETXTBSY there would pass it vacuously rather than fail it; the shared writer removes that masking too.
- Tests: `written_script_is_executable_and_runs`, `unwritable_path_panics_loudly` (scan/testing.rs).
- Evidence, `cargo test --lib` x40 each: at c42a80c 0/40 failures (ping tests never tripped); helper body swapped to in-process `std::fs::write` + `set_permissions`, 13/40 failures, all `Text file busy (os error 26)` in the traceroute fake-script tests and the helper's own test; child-`sh` helper restored, 0/40.
### Deviations
- None.
### Tradeoffs
- Module under `src/scan/` vs a crate-level `src/testing.rs`: every caller is a scanner test, and `src/tui/testing.rs` sets the per-area precedent.
### Open questions
- None.

## Phase 6: Registrable domain and RDAP bootstrap
### Design decisions
- One cache seam for both fetched files: `CachedSource::load(deadline, parse)` - src/scan/whois/cache.rs - fresh cache (<24h) is used as is; otherwise fetch within the deadline; a failed fetch falls back to a stale cache of any age; a cache file that does not parse is treated as missing; writes go to a temp file in the cache dir and `rename`; a write failure is logged at WARN and the fetched data is used in memory. Every branch logs file, cache age or error (`cache_fresh`, `cache_corrupt_treated_as_missing`, `refresh_failed_using_stale_cache`, `refresh_failed_no_cache`, `cache_write_failed`).
- A fetched body is parsed before it is written, so a captive-portal page or a truncated download never replaces a good cache - src/scan/whois/cache.rs:load.
- `parse_suffix_list` parses `IcannList`, and `parse_rdap_bootstrap` rejects an empty `services` list, so "corrupt" has a concrete meaning for each file - src/scan/whois.rs.
- `WhoisScanner` gains `rdap_bootstrap_url`, `psl_url`, `cache_dir: Option<PathBuf>`; the default `cache_dir` is `dirs::cache_dir()/scan` (`~/.cache/scan` on Linux) - src/scan/whois.rs:WhoisScanner::new - `None` (no platform cache dir) means fetch every lookup, logged.
- One `rdap_deadline = now + rdap_timeout` is taken before the suffix list load; the suffix list fetch, the bootstrap fetch and the RDAP query all run against it (`timeout_at`) - src/scan/whois.rs:scan_whois - so `deadline()` (30 + 15 + 5) is unchanged and still holds on a cold cache.
- The host is trimmed of a trailing dot and passed through `idna::domain_to_ascii` (lowercases and punycodes) before the suffix lookup - src/scan/whois.rs:registrable_domain.
- On suffix-list failure the WHOIS lookup runs on `normalized_host(host)` and the error is kept on the result - src/scan/whois.rs:scan_whois.
- `RdapBootstrap::base_url` prefers an `https://` URL among a service's URLs and normalizes the base to end in `/`; the query is `{base}domain/{domain}` (RFC 9224) - src/scan/whois.rs.
- `WhoisResult::domain_label()` owns the `Domain:` wording (`tatari.tv (from www.tatari.tv)`, `www.tatari.tv (suffix list unavailable: <e>)`, or the bare domain) for both the pane and `--no-tui` - src/scan/whois.rs, src/tui/whois.rs, src/pretty.rs.
- `NotApplicableReason { IpTarget, NoRegistrableDomain }` rides on `DataSource::NotApplicable(..)`; its `Display` is the gray reason text in both outputs, replacing the two copies of `"n/a for IP targets (see GEOIP)"` in src/tui/whois.rs and src/pretty.rs.
- Test fakes: `FakeHttp` (routes addable after bind, so `dns.json` can name the fake's own `/rdap/` base; per-path hit counts), `dead_http_url`, `silent_http_url`, `temp_dir` in src/scan/testing.rs; every accept and read is bounded by a 5s timeout. The module's cfg widened from `all(test, unix)` to `test`, with `write_executable_script` and its tests kept `unix`-only.
- Every test that builds a `WhoisScanner` sets a fresh `temp_dir` cache, including the pre-existing `test_whois_scanner_timeout` and the proxy-based fallback tests; `~/.cache/scan` did not exist after `otto ci`.
- Tests: src/scan/whois.rs `registrable_domain_is_the_icann_registrable_domain`, `host_without_a_registrable_domain_has_none`, `no_registrable_domain_scan_is_not_applicable_and_the_pane_says_why`, `rdap_base_url_reads_the_bootstrap`, `rdap_bootstrap_prefers_https_and_ends_the_base_in_a_slash`, `rdap_bootstrap_without_services_is_corrupt`, `suffix_list_without_an_icann_section_is_corrupt`, `scan_queries_rdap_for_the_registrable_domain_and_the_pane_shows_both`, `tld_without_rdap_service_skips_rdap_and_still_runs_whois`, `suffix_list_unavailable_runs_on_the_raw_host_and_says_so`, `second_lookup_within_24h_makes_no_fetch`, `cold_cache_fetch_counts_against_the_rdap_budget`, `domain_label_names_the_source_of_the_queried_domain`; src/scan/whois/cache.rs `a_second_load_within_24h_makes_no_fetch`, `a_cache_older_than_24h_is_refetched`, `a_stale_cache_is_used_when_the_refresh_fails`, `a_corrupt_cache_is_treated_as_missing_and_refetched`, `no_cache_and_a_failed_fetch_is_an_error_naming_the_url`, `a_fetched_body_that_does_not_parse_is_an_error_and_is_not_cached`, `an_unwritable_cache_dir_still_returns_the_fetched_data`, `the_fetch_is_bounded_by_the_deadline`; src/pretty.rs `whois_prints_the_queried_domain_and_its_source`, `whois_no_registrable_domain_prints_the_reason`. Each was shown failing with its fix undone (23 targeted breaks; one first attempt at the ICANN break, `List` converted back with `IcannList::from`, left the test green because that conversion re-applies the ICANN filter, so the break was redone with `psl::List` itself).
- Deleted, not inverted: `test_rdap_endpoint_selection` and `test_get_rdap_endpoint` pinned the deleted table; `rdap_base_url_reads_the_bootstrap` replaces them.
### Deviations
- `registrable_domain` returns `eyre::Result<Option<String>>` and both it and `rdap_base_url` take a `deadline` argument. `Ok(None)` is "no registrable domain" / "no RDAP service", kept apart from `Err` (source unavailable) because the two drive different outcomes (NotApplicable vs raw-host fallback; skip RDAP vs bootstrap error). Same effect, correct seam.
- `WhoisResult` gets `suffix_list_error: Option<String>` beside `queried_domain`. The doc names only `queried_domain`, but the pane must show `suffix list unavailable: <e>`, and the result is the only thing the pane sees.
- `DataSource::NotApplicable` carries a `NotApplicableReason`. The doc asks for NotApplicable "with the reason `no registrable domain`"; a reason field beside the variant would be a second signal for the same state.
- `--no-tui` WHOIS line now starts `<domain label> via <source>: ...` (e.g. `tatari.tv (from www.tatari.tv) via RDAP: 10yr old, ...`). The doc names only the pane; without this, `--no-tui` hid both the queried domain and the suffix-list degradation.
- A name `idna` rejects returns "no registrable domain" (NotApplicable) rather than the raw-host fallback; it is not a suffix-list outage, and the fallback label would claim one.
- The cache module lives at src/scan/whois/cache.rs (new file); the doc lists no file for it. whois.rs was already the largest scanner file.
### Tradeoffs
- File cache only vs also memoizing the parsed lists in memory: the scanner runs hourly, so a 24h file cache already makes repeat lookups fetch-free; an in-memory memo would add shared mutable state to a `Clone` scanner. Cost: with an unwritable cache dir every hourly lookup refetches (logged each time).
- Stale cache used with no age limit (per the doc) vs a ceiling: a year-old suffix list is still right for nearly every host, and the alternative is the raw-host degradation.
- Bootstrap and suffix list fetched serially inside one 30s budget vs in parallel: serial keeps the fetch of `dns.json` skipped entirely for hosts with no registrable domain; both fetches measured 33-116ms live.
### Open questions
- Live check, first cold-cache run of `www.tatari.tv` (release build, 21:12:40 UTC): the suffix list fetched in ~86ms, then the `https://data.iana.org/rdap/dns.json` fetch hung until the 30s RDAP deadline (`refresh_failed_no_cache: ... fetch timed out` at 21:13:10.641), so that run fell back to WHOIS (`Source: WHOIS`). Seven later cold and warm runs fetched `dns.json` in 33-109ms and showed `via RDAP`. The default INFO log does not record which stage hung (DNS, connect, TLS, body), and the system journal shows nothing for that window, so the stage is unidentified. Should the fetch get its own shorter bound (so a hung bootstrap fetch leaves RDAP budget for the query), or should `fetch` log per-stage timing at WARN on timeout so the next occurrence names its stage?

## Phase 6 amendment: bounded source fetches and fetch diagnostics
Supersedes the Phase 6 open question about the hung `dns.json` fetch (orchestrator ruling: do both the per-fetch limit and the diagnostics, amended into the Phase 6 commit).
### Design decisions
- Each suffix-list and bootstrap fetch gets `min(FETCH_TIMEOUT, time left on the deadline)`, `FETCH_TIMEOUT` = 10s - src/scan/whois/cache.rs:CachedSource::load - a hung fetch costs 10s of the 30s RDAP budget and leaves the RDAP query 20s; the fetch still counts against the budget, not on top of it.
- The limit is applied as reqwest's per-request `timeout` and as an outer `tokio::time::timeout`; the scanner's client also gets `connect_timeout(FETCH_TIMEOUT)` - src/scan/whois.rs:WhoisScanner::new.
- `WhoisScanner.source_fetch_timeout` (default `FETCH_TIMEOUT`) feeds `CachedSource.fetch_timeout`, so tests scale it down.
- On failure, `fetch_failed` logs at WARN with the URL, elapsed ms, the reqwest error class (set flags among `connect`, `timeout`, `request`, `body`, `decode`, joined with `+`, or `other`; `status` for a non-2xx answer; `deadline` when the outer timeout fires) and the `source()` chain. A success logs `fetch_succeeded` with elapsed ms and bytes at DEBUG - src/scan/whois/cache.rs:fetch, log_fetch_failure, reqwest_error_class, error_chain.
- The returned error names the limit on a timeout (`<url> fetch timed out after 10s`) and carries the source chain otherwise, because reqwest's own message (`error sending request for url (...)`) hides the cause.
- Tests: `hung_bootstrap_fetch_gives_up_at_the_fetch_limit_and_whois_still_runs` (src/scan/whois.rs: silent bootstrap server, cold cache, 300ms limit inside a 3s budget; the scan ends under 1.5s, the error starts `RDAP: RDAP bootstrap unavailable: ` and names `timed out after 300ms`, and the fake IANA WHOIS server got `tv`), `a_hung_fetch_gives_up_at_the_fetch_timeout_not_the_deadline` and `reqwest_error_class_names_a_refused_connect` (src/scan/whois/cache.rs). With the per-fetch limit undone (limit = time left on the deadline), the two hung-fetch tests fail (the run took 5.00s); with the class forced to `other`, the class test fails.
- Live, cold cache each time (`XDG_CACHE_HOME` set to a fresh scratch dir), `timeout 60 ./target/release/scan --no-tui www.tatari.tv`, 3 runs: all `✅ WHOIS: tatari.tv (from www.tatari.tv) via RDAP: ...` (71ms, 105ms, 241ms), no `fetch_failed` WARN line. The original hang did not happen again, so its stage is still unidentified; the next one will log its class and chain.
### Deviations
- reqwest has no per-request connect timeout; `connect_timeout` is client-wide, so it also bounds the RDAP query's connect at 10s. The per-request `timeout` (which covers connect, TLS and body) gives each fetch its exact limit.
### Tradeoffs
- 10s fixed constant vs a config field: the scanner has no config surface today, and the doc's 30s RDAP budget is also a constant.
### Open questions
- None.

## Phase 7: Readable sparkline
### Design decisions
- `SparklineData` holds `VecDeque<(Instant, Option<u64>)>`, µs, capacity 200 (`SPARKLINE_CAPACITY`) - src/tui/sparkline.rs - the timestamp is the ping result's `queried_at`, so the span label measures the sample times, not the render time.
- The bar math is pure functions over a visible window: `scale_max_us`, `bars_newest_first` (newest first, with the floor `max.div_ceil(rows * 8)`), `average_us`, `span` - src/tui/sparkline.rs - so the stepped scale, floor and order are unit-tested without a terminal.
- Sample recording: `Success` records `Some(µs)`, `Failed` and `ToolMissing` record `None`, `NoAddress` and `NotQueried` record nothing - src/tui/connectivity.rs:update_sparklines - a family with no address never pinged, so a red failure column there would claim a failure that did not happen.
- `connectivity_rows(inner)` returns `ConnectivityRows::Full` or `Compact`, a pure layout function - src/tui/connectivity.rs - full mode at `inner.height >= 1 + 2 * 2`; extra graph rows are split between the families, IPv4 takes the odd one.
- Compact label is `v4 <latest>`, padded to the wider of the two labels so both graphs start in the same column; the latest reads `✗` for a failed sample and `---` with no samples - src/tui/connectivity.rs:latest_text.
- Sub-ms latencies print with one decimal (`0.5ms`), whole ms above - src/tui/connectivity.rs:format_latency - the µs storage would otherwise still print `0ms`.
- Average, scale and span are computed over the visible samples, the ones the graph draws, not the whole 200-sample buffer.
- Failed sample symbol is `░` (`FAILED_SAMPLE_SYMBOL`) in red; it does not match the AC5 bar regex `[▁▂▃▄▅▆▇█]`.
- The scale label stays in ms at every step (`scale 0-5000ms`), one unit across the range.
- ratatui 0.29 API checked in `ratatui-0.29.0/src/widgets/sparkline.rs`: `direction(RenderDirection::RightToLeft)` places `data[0]` at the right edge, `absent_value_symbol`/`absent_value_style` exist, and `data` accepts `Option<u64>` via `From<Option<u64>> for SparklineBar`.
- Tests: src/tui/sparkline.rs `samples_are_stored_in_microseconds`, `a_failed_ping_is_recorded_not_dropped`, `capacity_drops_the_oldest_sample`, `visible_is_the_newest_width_samples_oldest_first`, `scale_is_the_smallest_step_at_or_above_the_peak`, `scale_without_a_reply_is_one_millisecond`, `average_counts_replies_only`, `span_runs_from_the_oldest_to_the_newest_timestamp`, `bars_are_newest_first_and_keep_failures_absent`, `a_reply_too_small_to_draw_is_raised_to_one_eighth_of_a_row`, `half_millisecond_reply_at_one_millisecond_scale_draws_a_bar`, `newest_sample_is_drawn_in_the_rightmost_column`; src/tui/connectivity.rs `failed_pings_are_recorded_as_absent_samples`, `compact_mode_at_80x24_draws_both_families`, `newest_sample_is_in_the_rightmost_column`, `failed_sample_renders_the_absent_symbol_under_a_scaled_title`, `full_mode_title_names_latency_scale_and_span`, `rows_are_compact_below_the_full_mode_height`, `rows_give_extra_height_to_the_graphs_in_full_mode`, `latency_formats_sub_millisecond_with_a_decimal`.
- Break-it: 13 targeted breaks (as_millis storage, failed pings dropped, no floor, bars oldest first, `LeftToRight` in the pane, unstepped scale, no compact mode, no absent symbol, no scale label, span from sample count, extra rows not given to graphs, sub-ms truncated in labels); each new test fails under at least one. The first version of `half_millisecond_reply_at_one_millisecond_scale_draws_a_bar` asserted only "non-blank" and stayed green under the as_millis break, because the floor raised the truncated 0 to one eighth; it now asserts the exact 4/8 glyph `▄`.
- Live, release build, `tui-test run --session ac --cols 80 --rows 24 -- ./target/release/scan google.com`: `expect text "[▁▂▃▄▅▆▇█]" --regex --timeout 30000` exit 0. Connectivity pane captured:
  ```
  ┌CONNECTIVITY──────────────────────────────────────────┐
  │🌐 Status: ipv4 only                                  │
  │v4 12ms                                     ▄▄▄▄▄▄▄▄▄▄│
  │v6 ✗                                        ░░░░░░░░░░│
  │                                                      │
  └──────────────────────────────────────────────────────┘
  ```
  At 200x55 the full-mode titles read `IPv4 13ms avg 12ms │ scale 0-20ms │ ← 5s` and `IPv6 no IPv6 route on this host │ scale 0-1ms │ ← 5s`.
### Deviations
- The Data Model says `VecDeque<Option<u64>>`; the Architecture says `(Instant, Option<u64>)`. Implemented the Architecture form, because the span label needs the timestamps.
- The full-mode title drops the old `📡 ` prefix and `:`, to read exactly as the doc's `IPv4 12ms avg 11ms │ ...`; the latency text format changes from `12ms avg:11ms` to `12ms avg 11ms`.
- Full mode has no blank spacer rows (the old layout had two); the doc's `1 + 2 × families` budget leaves none.
- Compact mode shows no scale or span label; at 54 columns the label plus scale would leave little graph. The scale still drives the bar heights.
- `MIN_CONNECTIVITY_PANE_HEIGHT` (12) is unchanged; nothing in the layout reads `min_size`, which is why the pane already renders at 6 rows.
- Outside the phase: `dead_http_url` (src/scan/testing.rs, Phase 6) freed its port after reading it, and `reqwest_error_class_names_a_refused_connect` failed `otto ci` in 2 of 4 runs with os error 104 (connection reset): a parallel test's server had bound the freed port, accepted, and reset. An unbound port answers 111 (refused), so 104 proves something accepted. The port now stays bound by a socket that never listens (still refused, never re-bound). Committed separately ahead of this phase as `test(scan): keep dead_http_url's port bound so a parallel test cannot take it`; 8 consecutive `cargo test --lib` runs and two `otto ci` runs green after.
### Tradeoffs
- Snapshot (clone) each family's `SparklineData` per render vs holding both locks through the draw: 200 small tuples per family per frame is cheap and keeps lock scope minimal.
- Stats over the visible window vs the whole buffer: the numbers match what the graph shows; on a narrow pane the average covers fewer samples.
- `std::mem::forget` on the reserved test socket vs a guard struct returned to callers: four call sites unchanged, one fd held per call for the test process lifetime.
### Open questions
- None.

## Phase 8: fit_line across panes
### Design decisions
- `fit_line(line, width)` - src/tui/text.rs - returns the line untouched when `Line::width() <= width`; otherwise walks each span's graphemes (ratatui `styled_graphemes`), measuring each with `Span::width` (unicode-width, the metric ratatui lays out with), keeps whole graphemes up to `width - 1`, and appends `…` in the style of the span being cut. Line `style` and `alignment` survive. Width 0 returns an empty line; width 1 returns `…`. A wide glyph that would straddle the cut is dropped, so the result can be one cell short.
- `fit_lines_except(lines, width, wrapped)` - src/tui/text.rs - fits every line except the indices in `wrapped`. Non-scrolling panes with a reason row (WHOIS, HTTP, PORTS, GEOIP) fit all lines but those, and render with `Wrap { trim: false }`; a fitted line never exceeds the width, so the wrap only ever acts on the reason rows.
- Reason rows that wrap: the `Status:` header in WHOIS, HTTP, PORTS and GEOIP (it carries `failed: <cause>`); the HTTP `plain HTTP (HTTPS failed: ...)` row; the WHOIS NotApplicable `Source:` reason; the WHOIS `Domain:` row only when it carries `suffix list unavailable: <e>`.
- TARGET has no reason row, so every line is fit (src/tui/target.rs:render). CONNECTIVITY gives its status a single row, so the status (including a failure reason), the full-mode family titles and the compact labels are fit, never wrapped (src/tui/connectivity.rs:render).
- DNS, SECURITY and TRACEROUTE fit every visible line after the scroll skip, at render time (src/tui/{dns,security,traceroute}.rs:render). The scroll math still counts logical lines from `build_content_lines`, unchanged.
- Converged on one helper: `ellipsize` is deleted. Every call site but one put the shortened value in the last span of its line, which `fit_line` covers by actual pane width instead of a fixed char count (DNS TXT and AAAA, SECURITY cipher, CSP policy, CSP/CORS issues, CORS origin, SPF, DMARC). The constants that fed it are deleted with it.
- The one mid-line use was the HTTP redirect row (`from → to (301)`, each URL cut to 35 chars). It now renders as two rows, `  301 <from>` and `    → <to>`, each fit to the width, so a long source URL cannot hide the target. `HttpPane::truncate_url` is deleted.
- Kept: the DNS `google-site-verification=...` / `MS=...` summaries and SECURITY `common_name_display`. They summarize content by meaning, not by width.
- Test helpers - src/tui/testing.rs: `dashboard_pane_size(row, col, cols, rows)` reads the cell size from `PaneLayout::create_grid_layout_public`, so the 80x24 and 108x40 widths come from src/tui/layout.rs, not hand-typed numbers. `expected_clip(source, width)` builds the expected `prefix…` char by char from the source text, independent of `fit_line`. `assert_clipped_in_narrow_terminals` renders the pane in its cell at both sizes and requires a row reading exactly `│<expected>` followed only by padding and `│`.
- Pane sizes used (outer, from layout.rs): 80x24: TARGET 24x6, CONNECTIVITY 56x6, the four middle panes 20x8, DNS 26x10, TRACEROUTE 27x10, SECURITY 27x10. 108x40: TARGET 32x10, CONNECTIVITY 76x10, middle 27x14, DNS 36x16, TRACEROUTE 35x16, SECURITY 37x16.
- Tests: src/tui/text.rs `line_that_fits_is_unchanged`, `truncates_across_spans_keeping_each_style`, `cut_inside_the_first_span_drops_the_later_spans`, `width_zero_renders_nothing`, `width_one_renders_only_the_ellipsis`, `wide_glyph_straddling_the_cut_is_dropped_not_split`, `multibyte_text_is_cut_on_char_boundaries`, `line_style_and_alignment_survive_the_cut`, `fit_lines_except_leaves_wrapped_rows_whole`; per pane at 80x24 and 108x40: `long_target_is_fit_with_ellipsis_in_narrow_terminals`, `long_failure_reason_is_fit_to_the_status_row_in_narrow_terminals`, `long_domain_is_fit_with_ellipsis_in_narrow_terminals`, `long_content_type_is_fit_with_ellipsis_in_narrow_terminals`, `long_service_name_is_fit_with_ellipsis_in_narrow_terminals`, `long_location_is_fit_with_ellipsis_in_narrow_terminals`, `long_txt_record_is_fit_with_ellipsis_in_narrow_terminals`, `long_ipv6_hop_is_fit_with_ellipsis_in_narrow_terminals`, `long_cipher_is_fit_with_ellipsis_in_narrow_terminals`; plus `protocol_line_is_fit_with_ellipsis_at_108_columns`, `protocol_line_that_fits_is_unchanged` (200x55), `long_redirect_target_url_is_fit_on_its_own_row`, `long_multibyte_redirect_url_is_fit_by_display_width`, `long_multibyte_txt_record_is_fit_by_display_width`, `suffix_list_failure_on_the_domain_row_wraps_instead_of_clipping`, `domain_from_host_is_intact_at_200x55`, `reached_and_silent_labels_are_intact_at_200x55`, `full_mode_title_is_intact_at_200x55`, `dashboard_pane_sizes_follow_the_layout_percentages`, `expected_clip_keeps_a_prefix_one_cell_short_of_the_width`.
- Break-it: (1) `fit_line` returning its input: 20 tests fail, every per-pane clip test plus the `fit_line` unit tests. (2) letting a wide glyph straddle the cut: `wide_glyph_straddling_the_cut_is_dropped_not_split` fails (`ab🦀…` vs `ab…`). (3) fitting the reason rows too: `fit_lines_except_leaves_wrapped_rows_whole`, `suffix_list_failure_on_the_domain_row_wraps_instead_of_clipping` and the existing `render_plain_http_fallback_names_https_failure_and_grade_f` fail. (4) unwiring every pane (pane call sites swapped for identity functions, `fit_line` intact): all 13 per-pane clip tests fail.
- Live, release build of this tree, harness as in the doc (`tui-test run --session ac --cols 200 --rows 55 -- ./target/release/scan <target>`, `zz-never` 55s wait exit 1 each time, checks, `tui-test close --all`): AC1 `Domain: tatari.tv` 0, `Source: RDAP` 0, `✓ reached` 0; AC2 `Source: RDAP` 1 (see Open questions); AC3 `operation timed out` 0, `scan failed --not` 0; AC4 `disconnected --not` 0, `no echo reply` 0; AC5 (80x24) bar regex 0; AC6 `8080/tcp (http-alt)` 0.
- Live clipping captures of `www.tatari.tv` at 80x24 and 108x40: every line too long for its pane ends in `…` (for example `🔗 Protocol: IPv4+IPv6 (Press…` at 108x40, `🌐 Domain: tatari.tv (fr…`, `🔑 Cipher: TLS13_AES_128…` at 80x24); no line is cut mid-word without one. At 80x24 the WHOIS, HTTP and PORTS status headers wrap their label onto a second row, as reason rows do.
### Deviations
- The doc says failure and status-reason lines wrap in non-scrolling panes. CONNECTIVITY is non-scrolling, but its status has a one-row area (Phase 7 layout), so wrapping would hide the overflow; its status line is fit instead.
- The HTTP redirect row became two rows (`  <code> <from>` and `    → <to>`). This was not in the doc; it is what removing `ellipsize` needs so the target URL stays visible.
- The HTTP per-pane fixture at 80x24 uses the content type, not a URL: at 80x24 the pane has 6 inner rows and the redirect rows fall below them. The redirect URL clip is tested at 108x40.
### Tradeoffs
- Fitting at render time in the scrolling panes vs inside `build_content_lines`: rendering knows the width; `build_content_lines` and the scroll math stay width-free and still count logical lines.
- Index list of wrapped rows vs a tagged line type: four panes, at most three reason rows each; an index list changes only the push sites that matter.
- Deleting `ellipsize` vs keeping it for the redirect row: a fixed 35-char cap does nothing useful in an 18-cell pane, and two helpers for the same job is what the phase asked to avoid.
### Open questions
- AC2 (`web.dev`, `Source: RDAP`) exits 1 at 200x55, and not because of clipping: WHOIS does retrieve over RDAP, but web.dev's result needs 21 rows (4 NS, 6 status rows, a risk header and its item) and the WHOIS pane has 17 inner rows at 200x55, so `Source:` lands below the bottom border. At 200x70 the same check exits 0 and the pane shows `📡 Source: RDAP`. No line in that capture is wrapped or fit, so Phase 8 does not change the row count. Fixing it needs a WHOIS layout change (move `Source:` up, collapse status rows, or make WHOIS scroll), which no phase in this doc covers. Which one do you want, or should AC2 be re-scoped?

## Phase 8 amendment: WHOIS Source under Domain (AC2)
### Design decisions
- `📡 Source:` now renders directly after `🌐 Domain:` in the retrieved-data path, and the old row at the bottom of the pane is deleted - src/tui/whois.rs:render - Scott's ruling on AC2. The color mapping is unchanged (RDAP green, WHOIS yellow, NotApplicable gray). The NotApplicable path already rendered `Target:` then `Source:`, and is unchanged.
- Cause of the AC2 failure: `web.dev` returns 4 name servers, 6 status items and 1 risk, so the pane needs 21 rows; at 200x55 WHOIS has 17 inner rows and `Source:` was row 21. At 200x70 the same run showed `📡 Source: RDAP`, so retrieval was fine and only the row position was wrong.
- Test: src/tui/whois.rs `source_stays_visible_under_long_ns_and_status_lists_at_200x55`, a web.dev-shaped fixture rendered at the WHOIS cell size for 200x55 (`dashboard_pane_size(1, 0, 200, 55)`, 50x19). It asserts `Source: RDAP` is visible and sits on the row right after `Domain: web.dev`. On the f67a527 code it fails (`Source pushed below the pane`); with the move it passes.
- Live after the fix, release build, same harness (200x55, `zz-never` 55s wait exit 1 each time): AC1 `Domain: tatari.tv` 0, `Source: RDAP` 0, `✓ reached` 0; AC2 (`web.dev`) `Source: RDAP` 0. The WHOIS pane now reads `🌐 Domain: web.dev` then `📡 Source: RDAP` on the next row.
### Deviations
- None.
### Tradeoffs
- Moving `Source:` up vs collapsing status rows or making WHOIS scroll: the ruling picked the move; it keeps every row and costs no scroll state.
### Open questions
- None.
