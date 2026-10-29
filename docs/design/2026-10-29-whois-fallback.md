# Design Document: Working WHOIS Fallback

**Author:** Scott Idler
**Date:** 2026-10-29
**Status:** Implemented
**Review Passes Completed:** 0/5 (written after the code, as a targeted fix; review-panel audit only)

## Summary

The traditional WHOIS fallback behind RDAP has never returned data. This replaces the `whois-rust` crate with a small async WHOIS client (RFC 3912, port 43) that follows IANA's referral to the registry, then the registry's referral to the registrar. The whole lookup runs under one hard timeout. A date-parsing gap found during the live check is fixed alongside it.

## Problem Statement

### Background
- `WhoisScanner` (`src/scan/whois.rs`) tries RDAP first and falls back to traditional WHOIS when RDAP fails.
- Found during the runtime-bug-fixes Phase 9 work and recorded in `docs/design/2026-10-29-runtime-bug-fixes-implementation-notes.md` as out of scope. The owner chose to ship v0.5.5 first, then fix this.

### Problem
- `WhoisScanner::new` built the `whois-rust` client from `WhoIs::from_path("/usr/bin/whois")`, then `WhoIs::from_string("whois")`. Both expect a JSON TLD-to-server map, so both fail: one gets an ELF binary and the other is not JSON.
- The last fallback, `WhoIs::from_host("whois.iana.org")`, has an empty TLD map. Every domain lookup returned `No whois server is known for this kind of object.` without opening a socket.
- The `whois-rust` lookup is blocking I/O. Phase 9 moved it to `spawn_blocking`, but its DNS step has no timeout and its socket timeout applies per read. The thread had no hard bound (round-2 audit, deferred to this fix).
- Found during the live check: `parse_whois_date` rejects RFC 3339 dates with fractional seconds and a numeric offset. MarkMonitor sends `1997-09-15T07:00:00.000+00:00`, so google.com came back with no dates.

### Goals
- The fallback returns registrar, dates and nameservers for domains whose TLD has a WHOIS server.
- A TLD with no WHOIS server fails with a reason that names the TLD.
- The fallback has one hard time limit and holds no blocking thread, including DNS resolution of the WHOIS servers.
- A registrar refusal or stall never discards a good registry answer, and no answer without registration data counts as success.

### Non-Goals
- Excluded: changing RDAP endpoint selection or making RDAP the subject of this fix.
- Excluded: IP WHOIS (still parked in the runtime-bug-fixes doc).
- Excluded: following more than one referral past the registry.

## Proposed Solution

### Architecture
- `WhoisScanner` drops the `whois_client: Arc<WhoIs>` field and gains `iana_server: String` (`whois.iana.org:43`). The field exists so tests can point the lookup at a local server.
- `query_traditional_whois(domain)` wraps `lookup_whois_text(domain)` in `tokio::time::timeout(whois_timeout)` (15s). On timeout it errors `WHOIS lookup timed out after 15s`.
- `lookup_whois_text(domain)`:
  1. Query IANA with the TLD. Read `whois:` / `refer:` for the registry server. If there is none, error `IANA lists no WHOIS server for .<tld>`.
  2. Query the registry with the domain.
  3. If the registry answer names a different `Registrar WHOIS Server:`, query that too. If that query fails, keep the registry answer.
- Free functions:
  - `whois_query(server, query)`: `tokio::net::TcpStream`, writes `query\r\n`, reads to EOF, caps the answer at 1 MiB, and errors on an empty answer.
  - `whois_referral(text)`: finds the next server named in an answer.
  - `with_whois_port(server)`: appends `:43` when there is no port.
- `parse_whois_date` tries `DateTime::parse_from_rfc3339` before the existing format list.
- `whois-rust` is removed with `cargo remove whois-rust`.
- Unchanged: `deadline()` (RDAP 30s + WHOIS 15s + 5s slack = 50s) and `DataSource::Failed(String)` carrying both errors.

### Implementation Plan

#### Phase 1: Async WHOIS client and date fix
**Model:** opus
- Everything in Architecture above, plus tests.
- **Success criteria:**
  - Against three local fake servers, `traditional_whois_follows_iana_and_registrar_referrals` asserts each server receives the expected query and the result has the registrar and creation date.
  - `traditional_whois_is_bounded_by_its_timeout`: a silent server errors with `timed out` within 2s, given a 300ms limit.
  - `whois_date_parses_fractional_seconds_and_offset` passes.

#### Phase 2: Audit fixes
**Model:** opus
- Added 2026-10-29 from the implementation audit (`~/.cache/review-panel/runs/PLSPs2UH/synthesis.md`). Probes A to C reproduced each must-fix.
- **Per-hop budget inside one bound (must-fix 1, panel Q1):** one deadline, `Instant::now() + whois_timeout` (15s total).
  - IANA and registry are required hops, each under `timeout_at(deadline)`. A timeout errors `WHOIS lookup timed out after <Duration:?>`, using Debug formatting so a sub-second limit prints truthfully.
  - The registrar hop is optional data under the same `timeout_at(deadline)`. A timeout, transport error or refusal keeps the registry answer.
- **Refusals are not successes (must-fix 2):** add `has_registration_data(text)`, true when some line's key is a registrar, creation, expiry or name-server key that `parse_whois_text` reads.
  - A registrar answer without registration data is dropped, and the registry answer is kept.
  - A final answer without registration data errors `WHOIS answer from <server> has no registration data: <first non-empty line>`.
- **No blocking resolver (must-fix 3):** `whois_query` resolves the server host with the Hickory tokio resolver (`Resolver::builder_tokio()`, as `src/scan/dns.rs` does), then connects to a `SocketAddr`. A `host:port` that is already an IP literal skips resolution.
- **Oversized answers are loud (cheap win):** read up to the cap + 1 byte, and error `WHOIS answer from <server> exceeded 1 MiB` instead of truncating silently.
- **Referral keys (cheap win):** `whois_referral` accepts `whois:`, `refer:` and `Registrar WHOIS Server:` in any answer (IANA, registry or registrar). Only the registry's answer is followed.
- **Pane source label (cheap win):** the WHOIS pane prints `Source: RDAP`, `Source: WHOIS`, `Source: n/a` or `Source: Failed: <reason>` from a `DataSource` display method, not `{:?}`.
- **Fallback through the scanner path (AC5):** a test builds `WhoisScanner` with a reqwest client proxied through a local listener that answers CONNECT with 502, so RDAP fails. The IANA server points at local `fake_whois` servers.
  - It calls `Scanner::scan` on a domain target, which exercises `scan_whois`, the RDAP failure and the WHOIS fallback.
  - It renders the result through `tui::testing::render_pane` with the WHOIS pane, and asserts `Source: WHOIS` and the registrar name.
- **Success criteria:**
  - A silent fake registrar yields `Ok` with the registry's registrar and dates.
  - A registrar answering `Query limit exceeded` yields the registry's data.
  - A registry answering only `Query limit exceeded` errors `has no registration data`.
  - A 1 MiB + 1 byte answer errors `exceeded 1 MiB`.
  - The scanner-path test passes.
  - Each test fails with its fix undone.

## Acceptance Criteria

- [x] **AC1** `otto ci` exits 0.
  - Observed after Phase 1 (uncommitted diff on `fix-whois-fallback`): exit 0, 308 tests pass.
  - Observed after Phase 2 (uncommitted diff): exit 0, 318 tests pass.
- [x] **AC2** `rg -n -i "whois-rust|whois_rust" --glob '!Cargo.lock' --glob '!docs/design/**' .` returns no match.
  - Observed: no match.
- [x] **AC3** The new tests fail when their fix is undone.
  - Observed:
    - Dropping the `registrar whois server` key fails 2 tests.
    - Raising the overall timeout to 3600s fails `traditional_whois_is_bounded_by_its_timeout` (30.00s).
    - Removing the RFC 3339 branch fails the date test.
  - Observed for Phase 2, one mutation each, each failing its test:
    - Registrar timeout returns an error: the silent-registrar test fails `WHOIS lookup timed out after 500ms`.
    - Registrar answer accepted without the data check: the refusing-registrar test fails `has no registration data: Query limit exceeded`.
    - Final data check removed: the registry-refusal test gets `Ok` with no registrar or dates.
    - Read capped at 1 MiB instead of 1 MiB + 1: the oversize test gets `Ok`.
    - Pane label back to `{:?}`: the scanner-path test finds no `Source: WHOIS`.
    - Timeout message back to `as_secs()`: the timeout test gets `timed out after 0s`.
- [x] **AC4** Live: `query_traditional_whois("google.com")` (temporary probe test, since removed) returns registrar `Markmonitor Inc.`, created 1997-09-15 and expires 2028-09-13.
  - Observed: as stated.
  - Also observed: github.com and wikipedia.org (MarkMonitor), tatari.tv (Gandi SAS) all return dates. example.dev errors `IANA lists no WHOIS server for .dev`.
- [x] **AC5** The TUI WHOIS pane shows `Source: WHOIS` data for a domain whose RDAP fails.
  - Observed: `scan_falls_back_to_whois_when_rdap_fails_and_the_pane_shows_it` passes. RDAP fails through a proxy that answers CONNECT with 502, `Scanner::scan` falls back to three local WHOIS servers, and the rendered pane shows `Source: WHOIS` and `Fixture Registrar`.
  - Observed after Phase 2, same fault injection on the release build: `WHOIS: 29yr old, expires in 1yr, Unknown privacy, Markmonitor Inc. (285ms, 2 risks)`.
  - Observed via fault injection: with RDAP forced to fail through an unreachable `HTTPS_PROXY`, v0.5.5 `--no-tui google.com` printed `WHOIS: No whois server is known for this kind of object.`, and this tree printed `WHOIS: 29yr old, expires in 1yr, ... Markmonitor Inc. (293ms)`. The proxy also breaks the other HTTPS scanners in that run.

## Alternatives Considered

### Shell out to the system `whois` binary
- **Pros:** it handles referrals itself. `scan` already shells out to ping and traceroute.
- **Cons:** it adds a runtime dependency on a binary that may be missing, and output varies by version.
- **Why not chosen:** the referral chain takes about 40 lines of async code, and that code is testable against local servers.

### Ship a TLD-to-server JSON map to `whois-rust`
- **Cons:** the map is data that goes stale, and the lookup stays blocking with no hard bound.
- **Why not chosen:** it fixes the empty map but not the time-limit defect.

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| A registry returns a referral with a scheme or trailing slash | Med | Low | `whois_referral` strips `whois://` and a trailing `/`; tested |
| A registrar server rate-limits or refuses | Med | Low | registry answer is kept |
| A server returns non-UTF-8 text | Low | Low | `String::from_utf8_lossy` |

## Open Questions

None.

## References
- RFC 3912 (WHOIS protocol)
- `docs/design/2026-10-29-runtime-bug-fixes.md`, and its implementation notes (Phase 9 amendment, Q1)
