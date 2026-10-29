# Implementation Notes: Working WHOIS Fallback

Design doc: `docs/design/2026-10-29-whois-fallback.md`

## Phase 1: Async WHOIS client and date fix
### Design decisions
- Replaced `whois-rust` with an async RFC 3912 client: IANA, then the registry, then the registrar the registry names — `src/scan/whois.rs:lookup_whois_text`, `whois_query` — the crate's TLD map was always empty, and its blocking I/O had no hard bound.
- `iana_server` is a field (`whois.iana.org:43` in production) — `src/scan/whois.rs:WhoisScanner` — so tests point the whole chain at local fake servers.
- `parse_whois_date` tries RFC 3339 before the format list — `src/scan/whois.rs:parse_whois_date` — MarkMonitor sends `1997-09-15T07:00:00.000+00:00`, which no listed format accepted.
- `fake_whois` bounds each `accept()` with a timeout — `src/scan/whois.rs:tests::fake_whois` — the first version blocked forever when a referral was missed and hung the suite; now a missed connection ends the server and the test fails on its query assertions.
### Deviations
- The date fix was not in the original plan. It was found during the live check: google.com came back with a registrar and no dates.
### Tradeoffs
- Own ~40-line client vs shelling out to the system `whois` binary: no runtime dependency on a binary that may be missing or vary by version, and the chain is testable against local servers.
### Open questions
- None.

## Phase 2: Audit fixes
### Design decisions
- One deadline, `tokio::time::Instant::now() + whois_timeout`, shared by all hops through `timeout_at` — `src/scan/whois.rs:lookup_whois_text`, `required_hop` — a registrar stall now costs the rest of the budget but never the registry answer, and the 50s scan deadline still holds.
- `query_traditional_whois` no longer wraps the lookup in an outer `timeout` — `src/scan/whois.rs:query_traditional_whois` — every network hop is already under the deadline; only CPU-bound parsing runs after it.
- Registration-data keys live in four shared constants that both `parse_whois_text` and `has_registration_data` read — `src/scan/whois.rs:WHOIS_REGISTRAR_KEYS` and siblings — the check and the parser cannot drift apart.
- `connect_whois_server` tries each resolved address in order — `src/scan/whois.rs:connect_whois_server` — a host whose first answer is an unreachable IPv6 address still connects over IPv4.
- The pane label is a `Display` impl on `DataSource` — `src/scan/whois.rs:DataSource`, used by `src/tui/whois.rs` — the label is defined once, next to the enum.
- Fake servers bound every accept and read with `FAKE_SERVER_WAIT` (2s), including the new `silent_whois` and `refusing_proxy` helpers — `src/scan/whois.rs:tests` — no fake server can hang a test.
### Deviations
- `has_registration_data` also requires a non-empty value, so `Registrar:` with nothing after it is not data. The spec only names the keys; an empty value carries no registration data, and the parser would store an empty registrar name.
- The WHOIS pane's `NotApplicable` branch still prints `Source: n/a for IP targets (see GEOIP)`, from the earlier runtime-bug-fixes work, not the bare `Source: n/a` label. That branch never reaches the generic `Source:` line. `DataSource::NotApplicable` displays as `n/a` and is tested.
- Must-fix 3 (no blocking resolver) has no break-it test. Switching `connect_whois_server` back to `TcpStream::connect(&str)` (tokio's `spawn_blocking` resolver) still passes `whois_query_resolves_a_hostname_server`, because the two resolvers return the same answer for `localhost`. The fix is checked by reading the code: a hostname goes only through `Resolver::builder_tokio()`, and a socket-address literal skips resolution.
### Tradeoffs
- A Hickory resolver built per WHOIS query vs one cached on the scanner: at most three queries per lookup once an hour, so the extra builds are negligible and the scanner keeps no resolver state. `Resolver::builder_tokio()` reads the system resolver config from disk, as `src/scan/dns.rs` already does.
- Error on an answer over 1 MiB vs truncate: a truncated answer looked complete. An oversized registrar answer now falls back to the registry answer through the optional-hop path.
- The scanner-path test fails RDAP with a local proxy that answers CONNECT with 502 vs an RDAP endpoint override: no production seam is added only for tests.
### Open questions
- `test_whois_scanner_timeout` (pre-existing) still reaches the real RDAP and IANA servers and passes on either outcome. Keep it, or replace it with the local scanner-path test?

## Orchestrator ruling on the Phase 2 open question

- `test_whois_scanner_timeout` stays as is. Making pre-existing network-hitting tests hermetic is an explicit non-goal of `docs/design/2026-10-29-runtime-bug-fixes.md`. The new local scanner-path test covers the fallback path deterministically.
