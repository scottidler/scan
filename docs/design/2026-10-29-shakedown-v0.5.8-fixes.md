# Design Document: Shakedown Fixes After v0.5.8, Observatory Grading, and New Target Lenses

**Author:** Scott Idler
**Date:** 2026-10-29
**Status:** Implemented
**Review Passes Completed:** 5/5

## Summary

A tui-test shakedown of the installed v0.5.8 across 15 targets found 7 correctness defects and 6 cosmetic ones. Scott asked for two more things in the same session: the HTTP grade must score a site exactly as MDN HTTP Observatory does, and a set of new per-target lenses (timing breakdown, ALPN, security.txt, MTA-STS). This doc fixes the defects, ports Observatory's retriever and grader, and adds the lenses.

## Problem Statement

### Background
- v0.5.8 shipped `docs/design/2026-10-29-shakedown-v0.5.7-fixes.md`.
- Scott asked "ok back to the test tui shakedown. how is it now?". The shakedown ran on ripr against `scan v0.5.8` (main `38aa3bf`). Captures: session scratchpad `sd3/`.
- Scott on the HTTP grade: "must make our grader to adhere to what http observatory does exactly. scan and it should score a website identical".
- Scott on the lenses: "add all of that to the next design doc".
- Observatory source: `mdn/mdn-http-observatory` at `2776308b4f02c49da1c991144c8e08d1fd8d05b6` (package 1.7.2), cloned to `~/repos/mdn/mdn-http-observatory`. The live API reports `algorithm_version: 6`, equal to `ALGORITHM_VERSION` at `src/constants.js:76`.
- Anchors: scan `path:line` at `38aa3bf`; Observatory `file:line` at `2776308`.
- The request shape changes the answer. `curl -s -D - https://www.google.com/` from ripr, 2026-10-29, counting `Strict-Transport-Security` lines:

| User-Agent | HTTP/1.1 | HTTP/2 |
|---|---|---|
| `curl/8` | 0 | 0 |
| `scan/1.0` | 0 | 0 |
| Observatory's Firefox UA | 1 (`max-age=31536000`) | 0 |

  Observatory (HTTP/1.1, Firefox UA) grades google.com `hsts-implemented-max-age-at-least-six-months`; scan v0.5.8 reports `Missing HSTS`. Matching Observatory's UA, Accept headers and HTTP/1.1 is part of the port, not a detail.

### Problem

#### Shakedown defects

| # | Defect | Root cause | Evidence |
|---|---|---|---|
| 1 | DNS reads `TTL: expired, refreshing` for ~10s of every cycle on TTLs ≤60s; nothing is refreshing | `requery_delay` schedules at exactly `queried_at + ttl` (`src/scan/dns.rs:245-251`); `ttl` is the stub's truncated whole-second remainder (`:43-46`), so the re-query lands in the cache entry's last second and gets TTL 0; the delay clamps to the 10s floor (`:21`) while `ttl_span` (`src/tui/dns.rs:395-398`) says `refreshing` | `sd3/ttl-series.txt`: `expired, refreshing` t=60..68 and t=131..137; log alternates `delay=57308ms`, `delay=10000ms` |
| 2 | `PTR: Failed` in BAD for an address with no PTR record | `reverse_lookup` error arm (`src/scan/dns.rs:876-877`) and status block (`:888-900`) treat no-records as a failure; `timed_lookup` checks `is_no_records_found() \|\| is_nx_domain()` (`:299`), PTR does not | `tatari-200.txt`, `dead-200.txt` fg 9 |
| 3 | Zoomed certificate chain lists the leaf twice (`4 certificates`, server sends 3) | `analyze_certificate_with_openssl` pushes `peer_certificate()` (`src/scan/tls.rs:719-721`), then all of `peer_cert_chain()` (`:724-730`), which already holds the leaf on the client side | `zt-01`: `Certificate Chain: 4 certificates`; same serial on `[0]` and `[1]`; `openssl s_client -showcerts` shows 3 |
| 4 | WHOIS `Privacy: open (contacts visible)` for redacted RDAP contacts; zoom shows empty `Name:` | `"fn"` stores `Some("")` (`src/scan/whois.rs:623-626`); redaction only from a `REDACTED FOR PRIVACY` remark (`:585-597`), RFC 9537 `redacted` array ignored; `assess_privacy_level` treats `name.is_some()` as visible (`:712-726`); `contact_lines` prints the empty value (`src/tui/whois.rs:66-69`) | `tatari-200.txt:28`; `zt-14`; `rdap.nic.tv` answer `["fn",{},"text",""]` with `redacted` listing "Registrant Name" |
| 5 | Each retained DNS result costs ~1 MB: RSS climbs ~10 MB while the 10-result history fills, then levels off | bounded retention, not a leak: the runner keeps 10 results per scanner (`src/scanner.rs:235`); what makes one `DnsResult` ~1 MB is not yet named (suspects: the parsed suffix list or raw answers held in the result) | google.com `--no-tui`: 21.7 MB at 20s, 31408 KB at 660s, 31548 KB at 900s (+140 KB after the history is full); the shakedown's 8-minute window ended before the plateau |
| 6 | HTTP shows `checking...`, `measuring...`, `detecting...` under `failed: … · ↻ retrying` | `src/tui/http.rs:291-309` suppresses placeholders only for `ScanStatus::Failed`; a `Running` scanner with `error` set falls through; `Server:` is never collected | `example8443-200`, `expired-200`, `selfsigned-200`, `neverssl-200`, `dead-200` |
| 7 | `localhost`: Target `✅ IPv6: ::1`, Connectivity `no IPv6 address` | Target rows come from hickory's answer (`src/tui/target.rs:171-193`), which returns `::1`; scanners use the system resolver, and `/etc/hosts` maps localhost only to 127.0.0.1 | `localhost-200`, log `resolved_ips=[127.0.0.1]` |

Cosmetic:

| # | Defect | Root cause |
|---|---|---|
| 8 | Target hides one row at 200x55 (`↓ 1 more`) | 13 content rows in 12 inner rows; the protocol hint has its own row (`src/tui/target.rs:238-259`) |
| 9 | `1 records`, `1 domains`, `1 indicators` | counts formatted without plural (`src/tui/dns.rs` section headers, `status_display:384`; `security.rs` SAN; `whois.rs` risks) |
| 10 | DNS sections lay out TTL two ways; IP targets list `A: not queried` / `AAAA: not queried` | A/AAAA put TTL on its own row, CNAME/NS/TXT/CAA inline |
| 11 | Duplicate status rows: Ports `Status: completed` + `Scanned: completed`; Security `Status: failed: …` + `🔗 Status: failed` | two rows render one state |
| 12 | Ports pane height changes between scans | the `Scanned:` row is dropped while refreshing |
| 13 | `--no-tui` says `N timeouts`, the TUI says `no reply` | `pretty.rs` wording; both use `silent_hops()` |

#### HTTP grade is not Observatory's
- scan's grade is a home-grown penalty sum (`src/scan/http.rs:13-38`, `calculate_security_score` `:622-702`) over one reqwest GET with `Policy::limited(10)` (`:123-133`). Only the final response's headers are kept; the body is read only for its length (`:276-278`).
- Observatory (`src/scanner/index.js:24-75`, `src/retriever/retriever.js:39-119`):
  - two sessions (`http://host/`, `https://host/`), redirects followed by hand and every hop recorded;
  - a cookie jar across the chain; the HTML body parsed for meta CSP, meta referrer, `<script>` SRI;
  - a CORS preflight; the Chromium HSTS preload list;
  - 12 tests, a 21-bucket grade table with +/-, bonuses only when the penalty-only score is ≥ 90.
- Live today (`POST https://observatory-api.mdn.mozilla.net/api/v2/scan`): `google.com` `C-` 45 (6 failed); `www.tatari.tv` `B` 75. scan v0.5.8 grades google.com `B`.
- Gaps: no `http://` session or redirection test; no recorded route; no cookies; no body parsing; no preflight; no COOP/COEP/CORP; Referrer-Policy unscored; `X-XSS-Protection` penalized (Observatory does not test it); CSP graded by directive count; no HSTS floor or preload; duplicate headers not joined; UA `scan/1.0`; a cert failure forces F and falls back to plain HTTP (`:186-229`) where Observatory grades with `verified=false`; no status gate; 6 grades instead of 13; no score shown.
- Consumers of the HTTP grade: `src/tui/http.rs:205-215` (enum match, color), `src/tui/security.rs:98-205` (HTTP tuple), `src/pretty.rs:186-207`. `src/tui/security.rs:378-385` colors the TLS grade, which keeps its own enum (`src/scan/tls.rs:113-131`) and is unchanged.

#### Missing lenses
- No HTTP phase timing (DNS, connect, TLS, TTFB, transfer); reqwest exposes none.
- No ALPN (HTTP/2) or `alt-svc` (HTTP/3).
- No `/.well-known/security.txt`.
- No MTA-STS (`_mta-sts` TXT) or TLS-RPT (`_smtp._tls` TXT) beside SPF and DMARC.

### Goals
- Every shakedown defect fixed at its cited seam; the ~1 MB retained per DNS result explained, and dropped if it is data no pane reads.
- The HTTP grade, score and all 12 per-test results equal Observatory's for the same site.
- The lenses show in the HTTP and Security panes from data collected per target.

### Non-Goals
- Excluded: a speed-test pane. Scott asked "is it a worthy addition to scan or is it out of character?"; it ignores the target, burns bandwidth every cycle and skews ping and traceroute.
- Excluded: blocklist/reputation and certificate-transparency lookups. They depend on third-party services.
- Excluded: Observatory's API-only `www.` DNS fallback (`src/api/v2/utils.js:114-140`). The CLI does not do it, and scan's target resolution already fails loudly.
- Excluded: the MTA-STS policy file fetch (`https://mta-sts.<domain>/.well-known/mta-sts.txt`). The lens Scott agreed to is the TXT records; DNS stays DNS.
- Excluded: `pretty.rs` colors (carried).
- Parked, revisit when a user asks for it: the `Server:` header value (item 6 removes the placeholder instead).

## Proposed Solution

### Overview
- Shakedown fixes at the cited seams, after a spike that names the leaking allocation.
- `src/scan/observatory/`: a port of Observatory's retriever, analyzers and grader, tested against Observatory's own test vectors, verified against the live API.
- The HTTP scanner's grade becomes the Observatory grade; the old penalty code, `CspStrength`, `CorsSecurityLevel` and the `X-XSS` penalty are deleted.
- Lenses ride on the Observatory retriever (redirects, cookies, `alt-svc`) and two small additions (a timed probe, two TXT lookups).

### Architecture

- **DNS cadence (1):**
  - `requery_delay` schedules at `expires_at + DNS_REQUERY_GRACE` (1s), so the query reaches the stub after its cache entry expired and returns a fresh TTL. Clamp stays 10s..60s.
  - `ttl_span` reads `expired, refreshing` only while the DNS scanner is `Running`. An idle 0 reads `expired` in `MUTED`. The label then never claims work that is not happening.
- **PTR (2):** the PTR arm maps `is_no_records_found() || is_nx_domain()` to an empty answer, like `timed_lookup` (`src/scan/dns.rs:299`). Status `NoRecords` renders `PTR: none` in `MUTED`.
- **Chain (3):** push `peer_cert_chain()` only. Push `peer_certificate()` first only when the chain is absent.
- **RDAP redaction (4):**
  - Read RFC 9537 `redacted[].name.description` and map "Registrant Name" etc. to the contact role.
  - An empty `fn` is `None`, never `Some("")`.
  - `assess_privacy_level` (`src/scan/whois.rs:712`) judges name and email separately; today one flag gates both. A redacted or empty name with a visible email is partial, never `open` and never fully protected. Zoom prints `(redacted)` per withheld field, as the v0.5.7 doc specified.
- **Memory (5):** Phase 0a names what one retained `DnsResult` holds. If it holds data the panes never read (e.g. the parsed suffix list), Phase 2 drops it from the result. If every byte is displayed data, item 5 closes as expected retention, recorded in the notes, and Phase 2 is skipped.
- **HTTP placeholders (6):** a `Running` scanner with `error` set renders like `Failed`: no placeholders. The `💻 Server: detecting...` row is deleted.
- **localhost (7):** Target's address rows come from the scanners' resolution (the system resolver), the same source Connectivity uses. Two signals never encode one fact.
- **Cosmetic (8-13):**
  - Target: the protocol joins the Status row: `Status: 7/8 ✅ 1 🔄 · IPv4+IPv6 (p)`. 12 rows at 200x55.
  - One `plural(n, "record")` helper in `src/tui/text.rs` for every count.
  - DNS: every section puts TTL inline in its header; an IP target omits A/AAAA.
  - Ports: one status row; `Scanned:` deleted. Security: the `🔗 Status: failed` row deleted.
  - `pretty.rs` says `no reply`.
- **Observatory port (R1):** `src/scan/observatory.rs` + `src/scan/observatory/{retriever,session,headers,html,csp,cookies,hsts,redirection,sri,cors,referrer,xcto,xfo,corp,coop,coep,grade}.rs`, one file per upstream module. Each file carries an MPL-2.0 header (Resolved Decisions, 2026-10-30).
  - **Retriever** (`retriever.js`, `session.js`):
    - two sessions in parallel, `http://host/` and `https://host/`, reqwest `Policy::none` and a manual loop: 301, 302, 303, 307, 308, at most 10 hops, every response recorded, `Location` resolved by WHATWG URL rules (`url = "2.5.7"` is already a direct dependency, `Cargo.toml:33`);
    - HTTP/1.1 only, as Node's `http` module is (reqwest is built without `http2` today; keep it that way);
    - the 29 certificate-error codes retry the chain with verification off and `verified=false`; any other TLS/connect error makes that session absent;
    - `auto` = https session if present, else http;
    - UA `Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:129.0) Gecko/20100101 Firefox/129.0 Observatory/129.0`, Accept `text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8`, 9s per request, 10s per session;
    - each session owns its own cookie jar (`session.js:77`), filled from every hop's `Set-Cookie` (hand-written, mirroring tough-cookie's accept/reject rules as Phase 0c measures them); the cookies test reads the `auto` session's jar only (`cookies.js:93`);
    - the certificate retry keeps the jar and the redirect count and clears the redirect history (`session.js:173`); the auxiliary client differs between the normal and the fallback path (`session.js:103`, `:197`), and the port copies both;
    - a `GET /robots.txt` on the `auto` session's auxiliary client before the preflight (`retriever.js:73-78`); it adds cookies only on the cert-fallback path, where that client carries the jar;
    - `OPTIONS` preflight to the final URL with `Origin: https://http-observatory.security.mozilla.org`, `Access-Control-Request-Method: GET`;
    - body decoded as UTF-8; meta tags parsed only for `text/html` / `application/xhtml+xml`;
    - duplicate headers joined `", "` the Node way, `set-cookie` kept as a list, first-wins for Node's first-wins set.
  - Phase 5 ports what the code does, quirks included, not what its comments say. It reads `retriever.js` and `session.js` end to end before writing the retriever.
  - **Analyzers:** each upstream test ported with its result names and modifiers verbatim (table in Data Model). Parsers are hand-written to mirror the JS: an `onopentag`-style tag scanner for htmlparser2, `parseCsp`, the RFC 8941 token-item subset, the cookie attribute parser.
  - **Grade:** `uncurved = 100 + Σ negatives`, `with_credit = 100 + Σ all`; score = `with_credit` if `uncurved >= 90` else `uncurved`; floor 0, no cap; grade from `min(score - score % 5, 100)`.
  - **Status gate:** no `auto` response -> `SiteIsDown`, no grade; status not 2xx/3xx/401/403 -> `UnexpectedStatusCode`, no grade.
  - **What gets graded:** the host only, on ports 80 and 443, as Observatory does. The grade line names it: `Grade: C- (45) · google.com`.
  - **Hosts Observatory refuses:** an IP address (`InvalidHostNameIpError`, `src/api/v2/utils.js:40-55`) or a name with no dot (`:81-91`, e.g. `localhost`) gets no grade: `Grade: n/a (IP address)` or `Grade: n/a (not a public hostname)` in `MUTED`. Never F.
  - **No grade:** `SiteIsDown` and `UnexpectedStatusCode` read `Grade: none (site down)` / `Grade: none (HTTP <code>)` in `MUTED`; the failure itself shows in the status line as today.
  - **HSTS preload list:** Chromium `transport_security_state_static.json` through `CachedSource` (`src/scan/cache.rs`), comments stripped, `{include_subdomains, mode}` kept. The seed parked this "only if R1 needs it"; R1 needs it (`hsts-preloaded`, `redirection-all-redirects-preloaded`).
    - Same source as production: Observatory's `conf/hsts-preload.json` is gitignored (`.gitignore:5`; commit `7bbb7a4` deleted the checked-in copy) and written at image build by `npm ci`'s postinstall (`Dockerfile:11`, `package.json:30`) from Chromium's file (`src/retrieve-hsts.js:8`). `src/maintenance/index.js` can rewrite the file later, but `hsts.js:17` keeps the parsed map for the life of the process, so the API's list is Chromium as of when its analyzer process loaded it. scan's is Chromium as of its last successful refresh. A difference changes a result when the host's entry, a parent's entry, or any redirect hop's entry (`redirection.js:59-61`) changed in between; Phase 0b checks a preloaded host.
    - Ownership: one `HstsPreload` owned by `HttpScanner`, parsed once per refresh. At scan start, if the cached file is older than 24h, a refresh is attempted; a failed refresh keeps the copy in memory (`CachedSource` returns a stale copy of any age, `src/scan/cache.rs`).
    - Never an empty list by accident. With no fresh or stale copy, the list is treated as not containing the host: every test computes its normal result, exactly as for a host that is not preloaded, so the score stays defined and the cookies test (which reads the HSTS test's `pass`, `cookies.js:72`, `:122`, `:146`) needs no special case. `preload_available=false` is set and the grade line adds `· preload list unavailable` in `WARN`.
    - Lookup, as `hsts.js:38-57`: trim and lowercase the name; an exact entry matches only with mode `force-https`; otherwise walk each parent label up to the TLD, where a parent matches only with `force-https` and `include_subdomains`, and a non-matching entry on the way does not stop the walk. Source URL: `https://raw.githubusercontent.com/chromium/chromium/main/net/http/transport_security_state_static.json`.
  - **Production behavior wins over source:** where the deployed service behaves differently from the code as written (Phase 0 tests the CORS universal-access branch, which reads `response.request.headers.origin`, an undefined property on Node's `ClientRequest`), scan matches production and the notes record it.
  - **No per-family grade:** Observatory resolves normally and lets Node pick the address; it has no per-family result, and scan's pinning covers only the first host, not redirect targets (`src/scan/http.rs:121`). The Observatory run resolves normally too, once per scan, whatever `p` selects. The grade is a fact about the host, so the line names the host, not a family.
- **HTTP result model:** three outcomes, independent of each other:
  - **Target observation:** the URL as given (status, time, type, size, redirects), fetched per family as today (`request_plan`, `src/scan/http.rs:62`). It stays a separate fetch even for a plain host: it is pinned per family and follows `p`, while Observatory resolves normally, so one cannot stand in for the other.
  - **Observatory:** `Graded(ObservatoryResult)`, `NotApplicable(reason)` (IP address, dotless name), or `Failed(reason)` (site down, unexpected status, deadline).
  - **Lenses:** each `LensOutcome<T> = Present(T) | Absent | Failed(reason)`.
  - The scan returns `Err` only when the target observation and Observatory both fail. A lens failure never fails the scan. Each failed part shows its own reason in its own line; a part that succeeded is never painted failed because another part failed.
  - Examples: `https://example.com:8443/` times out while `example.com` grades: the status line reads the 8443 failure, the grade line reads `Grade: B (70) · example.com`. The grade fails while the URL works: `Grade: none (site down) · example.com` under a normal target block.
- **Budget:** `HttpScanner::deadline()` returns 40s (the runner default is 30s, `src/scanner.rs:12`). Inside it: target observation, Observatory and lenses run concurrently. Observatory's `http` and `https` sessions run concurrently (10s each), then robots.txt and preflight in order (9s each): 28s worst case. Each lens has its own 9s timeout. An inner 35s budget returns whatever finished, so the runner's deadline never discards a partial result.
- **HTTP scanner wiring:** `HttpData` carries `observatory: ObservatoryOutcome` and `lenses`. `HttpStatus::Success` no longer carries a grade. The penalty consts, `calculate_security_score`, `calculate_security_grade`, `CspStrength`, `CorsSecurityLevel`, `HttpVulnerability::InformationDisclosure` (never pushed) and the plain-HTTP F fallback are deleted.
- **Display:** HTTP pane `Grade: C- (45) · google.com`; colored by grade letter through `theme` (A -> GOOD, B/C -> WARN, D/F -> BAD) by matching the enum, as `src/tui/http.rs:205-210` does today. Zoom lists the 12 tests: name, result, modifier. The Security pane's HTTP section and `pretty.rs` show the same grade and host.
- **Lenses (R2):**
  - **Timing:** a probe in `src/scan/http/timing.rs` against the target URL as given (`request_plan`: scheme, host, port, path), pinned to the primary family's first address: timed hickory lookup, `TcpConnector::connect` (`src/scan/connect.rs:35`), a tokio-rustls handshake as in `src/scan/tls.rs:579-646` offering ALPN `http/1.1` only, then `GET <path> HTTP/1.1` with `Connection: close`. Boundaries: TTFB = request written -> first response byte; transfer = first byte -> end of body (`Content-Length` reached, terminating chunk, or close). A plain `http://` target reads `TLS: n/a`. Runs once per HTTP scan.
  - **ALPN:** a separate handshake to `host:443` offering `h2, http/1.1`, closed after the handshake with no request (RFC 9113 §3.4: an `h2` connection must speak HTTP/2, so the timed request never offers it). Shows the negotiated protocol. `alt-svc` comes from the `auto` response's headers (`h3` present -> HTTP/3 advertised).
  - **Redirect and cookies:** views of the Observatory retriever's `http` route and `auto` jar (Scott's lens list named "`http://` -> `https://` redirect check" and "cookie flags"). No second implementation.
  - **security.txt:** one GET of `https://host/.well-known/security.txt` on a verifying client (never the cert-bypass client). States: `present` (2xx, `text/plain`, a `Contact:`), `expired` (`Expires:` in the past), `invalid` (2xx text with no `Contact:` or an unparseable `Expires:`), `absent` (404, or 2xx `text/html`, the soft-404 case), `failed: <reason>` (timeout, TLS or connect error). RFC 9116.
  - **MTA-STS, TLS-RPT:** TXT at `_mta-sts.<host>` (`v=STSv1; id=`) and `_smtp._tls.<host>` (`v=TLSRPTv1; rua=`), the target host only, the same name SPF is read from. No parent-domain fallback: MTA-STS does not inherit to subdomains (RFC 8461 §3.4), and TLS-RPT is discovered at the policy domain (RFC 8460 §3). Results on `EmailSecurityAnalysis`, shown under DMARC in the Security pane.
  - `txt_at` (`src/scan/dns.rs:369-378`) folds a timeout or resolver error into an empty answer today. It returns the query status instead, so a DNS failure reads `failed`, not `none`.
  - Placement: HTTP zoom shows `ALPN:`, the timing row (`DNS · Connect · TLS · TTFB · Transfer`), `alt-svc:` and `security.txt:` before the header list; Security zoom shows `MTA-STS:` and `TLS-RPT:` under `DMARC:`. Each lens row shows its value, `none`, or `failed: <reason>`.

### Data Model
- `GradeLetter` enum: `APlus, A, AMinus, BPlus, B, BMinus, CPlus, C, CMinus, DPlus, D, DMinus, F`, `as_str` `"A+"`..`"F"`.
- Score buckets (`src/grader/charts.js:6-30`): 100 A+; 95, 90 A; 85 A-; 80 B+; 75, 70 B; 65 B-; 60 C+; 55, 50 C; 45 C-; 40 D+; 35, 30 D; 25 D-; 20..0 F.
- `ObservatoryOutcome = Graded(ObservatoryResult) | NotApplicable(String) | Failed(String)`.
- `ObservatoryResult { host, algorithm_version: u32 (6), score: i32, grade: GradeLetter, tests: Vec<TestResult>, verified: bool, preload_available: bool }`; `TestResult { name, result, score_modifier, pass }`.
- The 12 tests and modifiers (`src/constants.js:44`, `charts.js:107+`). Short names below; the code uses the full result names verbatim from `src/types.js` (e.g. `csp-not-implemented-but-reporting-enabled`, `hsts-header-invalid`), since the live test compares them as strings:

| Test | Result -> modifier |
|---|---|
| content-security-policy | default-src-none +10; no-unsafe +5; unsafe-inline-in-style-only 0; insecure-scheme-passive-only -10; unsafe-eval -10; unsafe-inline -20; insecure-scheme -20; header-invalid -25; not-implemented -25; not-implemented-but-reporting -25; duplicate-directives 0 |
| cookies | secure+httponly-sessions+samesite +5; secure+httponly-sessions 0; not-found 0; no-secure-but-hsts -5; session-no-secure-but-hsts -10; no-secure -20; samesite-invalid -20; anticsrf-no-samesite -20; session-no-httponly -30; session-no-secure -40 (worst wins) |
| cross-origin-resource-sharing | not-impl 0; public 0; restricted 0; universal -50 |
| redirection | all-preloaded 0; to-https 0; no-http 0; off-host-from-http -5; not-to-https-on-initial -10; not-to-https -20; missing -20; invalid-cert -20 |
| referrer-policy | private +5; not-impl 0; unsafe -5; invalid -5 |
| strict-transport-security | preloaded +5; ≥15552000 0; <15552000 -10; not-impl -20; invalid -20; no-https -20; invalid-cert -20 |
| subresource-integrity | impl+all-secure +5; impl+external-secure +5; not-html 0; no-scripts 0; all-from-secure-origin 0; not-impl-but-external-https -5; impl-but-external-not-secure -20; not-impl+external-not-secure -50; html-not-parseable -20 |
| x-content-type-options | nosniff 0; not-impl -5; invalid -5 |
| x-frame-options | via-csp +5; sameorigin/deny +5; allow-from 0; not-impl -20; invalid -20 |
| cross-origin-resource-policy | same-origin +10; same-site +10; cross-origin 0; not-impl 0; invalid -5 |
| cross-origin-embedder-policy | require-corp +10; credentialless +10; unsafe-none 0; not-impl 0; invalid -5 |
| cross-origin-opener-policy | same-origin +10; same-origin-allow-popups +10; noopener-allow-popups +10; unsafe-none 0; not-impl 0; invalid -5 |

- `LensOutcome<T> = Present(T) | Absent | Failed(String)`. On `HttpData`: `timing: LensOutcome<HttpTiming { dns, connect, tls: Option<Duration>, ttfb, transfer }>`, `alpn: LensOutcome<String>`, `alt_svc: LensOutcome<String>`, `security_txt: LensOutcome<SecurityTxt { state, contact, expires }>`.
- `EmailSecurityAnalysis`: add `mta_sts: LensOutcome<String>` (the `id`), `tls_rpt: LensOutcome<String>` (the `rua`).
- DNS: `DNS_REQUERY_GRACE: Duration = 1s`; PTR status gains `NoRecords`.

### API Design
```rust
// scan/observatory.rs
pub async fn observe(host: &str, pin: Option<IpAddr>, preload: &HstsPreload) -> ObservatoryResult;
pub fn grade(tests: &[TestResult]) -> (i32, Option<GradeLetter>);
// scan/observatory/retriever.rs
pub struct Retrieval { pub http: Option<Session>, pub https: Option<Session>, pub cors: Option<Response>, pub cookies: Vec<Cookie>, pub meta: MetaTags, pub auto_body: Option<String> }
// scan/http/timing.rs
pub async fn probe(host: &str, ip: IpAddr, port: u16) -> eyre::Result<(HttpTiming, Option<String>)>;
// tui/text.rs
pub fn plural(n: usize, noun: &str) -> String;
```

### Implementation Plan

Each phase: one commit, `otto ci` green, each new test shown failing with its fix undone.

#### Phase 0: Spikes (no scan code)
**Model:** opus
- **0a, memory:** measure the heap size of one `DnsResult` for google.com (serialize-size and a counted allocation around `perform_dns_lookup`), and list its largest fields. Confirm the plateau: RSS at 660s and 900s.
- **0b, Observatory oracle:** `npm ci` in `~/repos/mdn/mdn-http-observatory` (operator step if the sandbox blocks it). For google.com, www.tatari.tv, github.com (preloaded), example.com, mozilla.org and neverssl.com, run the local CLI and `POST /api/v2/scan` + `GET /api/v2/analyze` within the same minute. Record per test, with provenance: scan id, timestamp, effective URL, `verified`, the CLI's preload-list fingerprint (sha256), and the request headers the CLI sent.
- **0c, quirks:** (i) CORS universal access: a public host whose `OPTIONS` echoes `Origin` with credentials, graded by the API (production) and by the local CLI; if no such public host is found, record that and port the code as the local CLI runs it. (ii) an already-expired `Set-Cookie` and (iii) a cross-domain `Set-Cookie`, served by a crafted local server to the local CLI: record what tough-cookie keeps.
- **Stop condition:** a host whose local CLI result and API result differ, where the captured inputs do not explain the difference, stops the plan before Phase 4. It goes to Scott with the provenance. "Identical" is not weakened by moving a host off the list without his say-so.
- **Success criteria:**
  - The notes give the per-result size and its largest fields (0a), and say whether item 5 is waste (Phase 2 runs) or displayed data (Phase 2 skipped).
  - The notes hold the 0b table with every host marked identical or explained, and a result for 0c(i)-(iii), each one proven, refuted, or explicitly blocked with the reason.

#### Phase 1: Shakedown correctness fixes
**Model:** opus
- Items 1, 2, 3, 4, 6, 7.
- **Success criteria:**
  - Unit: `requery_delay` (injected `now`) returns 31s for records expiring in 30s, the 10s floor for 4s, and the 60s ceiling for 300s. `ttl_span` at 0 reads `expired, refreshing` while the DNS scanner is `Running` and `expired` otherwise.
  - Unit: a PTR no-records answer renders `PTR: none` in `MUTED`, and a PTR resolver error still renders `PTR: Failed` in `BAD`. A chain fixture of leaf + 2 renders `3 certificates`, and a fixture with no `peer_cert_chain()` renders the leaf alone.
  - Unit: three RDAP fixtures: empty `fn` + visible email reads partial (not `open`, not protected); a `redacted` entry for the name only reads partial; full redaction reads protected; zoom prints `(redacted)` for each withheld field.
  - `render_pane` HTTP with `Running` + `error` contains none of `checking...`, `measuring...`, `detecting...`. Target's address rows equal the scanners' resolved addresses for a localhost-style fixture (`127.0.0.1` only).

#### Phase 2: Memory growth
**Model:** opus
- Item 5, only if Phase 0a found data in `DnsResult` that no pane reads.
- **Success criteria:** one retained `DnsResult` for the google fixture drops below half its Phase 0a size, with a unit test that fails with the fix undone; RSS at 900s is lower than Phase 0a's 900s figure by at least 5 MB.

#### Phase 3: Cosmetic fixes
**Model:** sonnet
- Items 8-13.
- **Success criteria:**
  - Target at 200x55 renders with no `↓` marker, and its Status row contains the protocol.
  - A count-1 fixture renders `1 record`, `1 domain`, `1 indicator` in DNS, Security and WHOIS; every DNS section header carries its TTL inline; an IP-target DNS fixture renders no `A:` or `AAAA:` row.
  - Ports renders the same number of rows while refreshing and after; Ports and Security each render one status row; `pretty.rs` prints `no reply` for a silent-hop fixture.

#### Phase 4: Observatory analyzers and grader (pure, no network)
**Model:** opus
- `src/scan/observatory/*` analyzers, parsers and `grade`. Input is a `Retrieval` struct.
- Port every case in Observatory's `test/{csp,csp-parser,cookies,cors,redirection,referrer-policy,strict-transport-security,subresource-integrity,x-content-type-options,x-frame-options,cross-origin-resource-policy,cross-origin-embedder-policy,cross-origin-opener-policy,grader,analyzer-utils}.test.js`, with the HTML in `test/files/` and `test/fixtures/`.
- **Success criteria:**
  - The ported test count equals the upstream `it(` count in those files, and every ported case gives the upstream result and modifier.
  - A table test covers every grade bucket; score 89 (penalties only) drops all bonuses and 90 keeps them.
  - google.com's responses captured in Phase 0b, fed through the analyzers, grade `C-` 45 with the same 12 results the API returned.

#### Phase 5: Retriever and HSTS preload
**Model:** opus
- Two sessions, manual redirects, cert fallback, per-session jars, robots.txt, preflight, body and meta, header join, status gate; `HstsPreload` through `CachedSource`.
- Extend `FakeHttp` (`src/scan/testing.rs:44-112`) to serve per-path headers, `Location`, `Set-Cookie` and `OPTIONS`, plus a TLS mode with a test CA injected through the retriever's client builder.
- **Success criteria:**
  - Against `FakeHttp`: each of the eight redirection results is reproduced; two STS headers grade `hsts-header-invalid`; a cert the test CA did not sign grades with `verified=false` and the jar survives the retry; a robots.txt `Set-Cookie` reaches the jar only on the fallback path; a 500 gives `Failed(unexpected status)`.
  - Preload fixtures: an exact `force-https` entry grades `hsts-preloaded`; a parent with `include_subdomains` matches a child; a parent without it does not; a wrong mode does not; `  GitHub.COM ` matches `github.com`. With no cache and a dead URL, a fixture whose headers give `hsts-implemented-max-age-at-least-six-months` keeps that result and the same score as with a list that lacks the host, `preload_available=false`, and the grade line shows `preload list unavailable`.
  - A stalled `https` session hits its 10s cap and the scan still returns a target observation within 35s (tokio paused time).

#### Phase 6: Wire the Observatory grade into scan
**Model:** sonnet
- The result model, `HttpScanner::deadline()`, delete the old grade code, update `tui/http.rs`, `tui/security.rs`, `pretty.rs` and their tests. Zoom lists the 12 tests.
- The live test `scan::observatory::live::scan_matches_the_live_observatory_api` (`#[ignore]`, one test looping the hosts): for google.com, www.tatari.tv, github.com, example.com, mozilla.org and neverssl.com, a fresh `POST /api/v2/scan`, then `observe` and the API's tests compared per test (result string), score, grade and `algorithm_version` 6. A mismatch prints the provenance (scan id, timestamp, effective URL, `verified`, preload fingerprint). A host leaves the list only by a dated Resolved Decision with Scott's say-so.
- **Success criteria:**
  - `render_pane` HTTP for the google fixture shows `Grade: C- (45) · google.com` in `WARN`, zoom shows all 12 test names, and the Security pane and `pretty.rs` show the same grade.
  - An IP target reads `Grade: n/a (IP address)` and `localhost` reads `Grade: n/a (not a public hostname)`, both `MUTED`; a site-down fixture reads `Grade: none (site down)`.
  - A URL-fails/grade-works fixture shows the URL failure and the grade together, and the scan returns `Ok`; both failing returns `Err`. The live test passes.

#### Phase 7: Lenses
**Model:** opus
- Timing probe, ALPN handshake, `alt-svc`, security.txt, MTA-STS and TLS-RPT (with `txt_at` status), redirect and cookie views.
- **Success criteria:**
  - Against a local TLS fake: the timed request completes a valid HTTP/1.1 exchange with ALPN `http/1.1`, each phase is non-zero and they sum to within 5ms of the wall time; the ALPN handshake reports `h2` when the fake offers it and sends no request bytes; a plain-HTTP fake reads `TLS: n/a`; a fake that stalls after the handshake gives `Failed` for timing and the rest of the scan still returns.
  - security.txt fixtures give `present`, `expired`, `invalid`, `absent` (404 and soft-404 HTML) and `failed` (timeout).
  - A DNS fixture renders `MTA-STS:` and `TLS-RPT:` values; a resolver error renders `failed`, not `none`; the redirect and cookie views show the `http` route and the `auto` jar's flags for a fixture.

## Acceptance Criteria

All observed lines: installed `scan v0.5.8` (main `38aa3bf`) on ripr (no IPv6 default route), 2026-10-29/30.

Live checks run the installed binary: `tui-test run --session ac --cols 200 --rows 55 -- scan <target>`, wait with `tui-test --session ac expect text "zz-never" --timeout 55000` (exit 1 expected, a wait only), run the checks, then `tui-test close --all`.

- [ ] **AC1** `cargo test --release --lib -- --ignored --exact scan::observatory::live::scan_matches_the_live_observatory_api` prints `test result: ok. 1 passed`.
  - Observed on main: `test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 538 filtered out` (the test does not exist yet; a filter that matches nothing exits 0, so `0 passed` is the failing state).
- [ ] **AC2** `g=$(curl -s -X POST 'https://observatory-api.mdn.mozilla.net/api/v2/scan?host=google.com' | jq -r '"\(.grade) (\(.score))"')`; on `google.com`, `expect text "Grade: $g · google.com"` exits 0.
  - Observed on main: API `C- (45)`; `expect text "Grade: C- (45) · google.com"` exits 1.
- [ ] **AC3** `be.tatari.tv`: sample the screen every 2s for 180s (`tui-test --session ac text | rg -c 'TTL: expired'`); the longest run of consecutive samples containing `TTL: expired` is ≤ 2.
  - Observed on main: longest run 5 (10s).
- [ ] **AC4** `www.tatari.tv`: `expect text "PTR: none"` exits 0; `expect text "Privacy: "` exits 0 and `expect text "Privacy: open" --not` exits 0; `n=$(echo | openssl s_client -showcerts -connect www.tatari.tv:443 -servername www.tatari.tv 2>/dev/null | grep -c 'BEGIN CERTIFICATE')`, `key press Enter`, then `expect text "Certificate Chain: $n certificates"` exits 0.
  - Observed on main: `PTR: none` 1, `Privacy: ` 0, `Privacy: open --not` 1, `Certificate Chain: 3 certificates` 1 (openssl n=3).
- [ ] **AC5** `scan --no-tui google.com >/dev/null 2>&1 & P=$!; sleep 660; a=$(ps -o rss= -p $P); sleep 240; b=$(ps -o rss= -p $P); kill -0 $P && echo $((b-a))` prints a number < 1024 (KB): no growth after the history is full. A regression guard: it holds on main today.
  - Observed on main: `140` (31408 -> 31548 KB). Passes: the growth item 5 measured is bounded retention.
- [ ] **AC6** `google.com`: `key press Enter` (Security), `expect text "MTA-STS: $(dig +short TXT _mta-sts.google.com | sed 's/.*id=\([^;"]*\).*/\1/')"` and `expect text "TLS-RPT: $(dig +short TXT _smtp._tls.google.com | sed 's/.*rua=\([^;"]*\).*/\1/')"` exit 0. `github.com`: `key press shift+tab` ×5, `key press Enter` (HTTP), `expect text "┌HTTP"`, `expect text "ALPN: h2"`, `expect text "TTFB: \d+ms" --regex`, `expect text "security.txt: present"` exit 0.
  - Observed on main: google.com (id `20210803T010101`, rua `mailto:sts-reports@google.com`) 1, 1; github.com `┌HTTP` 0 (key path reaches HTTP zoom), `ALPN: h2` 1, `TTFB:` 1, `security.txt: present` 1.

## Resolved Decisions
- 2026-10-29: the speed-test pane is out of character; the timing breakdown replaces it (Scott asked; answered out of character).
- 2026-10-29: google.com is not HSTS-preloaded (Chromium list has only Google subdomains; `hstspreload.org` `unknown`). Superseded the same day: scan's `Missing HSTS` there is wrong, not correct. Google sends HSTS to a Firefox UA over HTTP/1.1 (Background table); scan's `scan/1.0` UA never sees it.
- 2026-10-29: "identical" means the same 12 per-test results, score and grade as Observatory, per the API.
- 2026-10-29: production behavior wins where it differs from Observatory's source; recorded in the notes.
- 2026-10-29: the HSTS preload list is in scope; R1 needs it.
- 2026-10-29: no `www.` fallback; it is API-only.
- 2026-10-29: `CspStrength` and `CorsSecurityLevel` labels are deleted; Observatory's per-test results replace them. Two signals never encode one fact.
- 2026-10-29: parsers are hand-written to mirror the JS, not new crates; fidelity to htmlparser2, tough-cookie and `parseCsp` is the requirement.
- 2026-10-29: MTA-STS is TXT only; no policy-file fetch from the DNS scanner.
- 2026-10-30: Scott chose A: port Observatory's logic and tests into `src/scan/observatory/*` under MPL-2.0 file headers; the rest of scan stays MIT. Both panel seats recommended it; a clean-room rewrite was not possible after reading the source.
- 2026-10-30, panel round 1 (Gemini + Codex), synthesis `~/.cache/review-panel/runs/z0POzIut/synthesis.md`: 7 must-fix and 7 cheap-win folded in:
  - The HTTP result is three independent outcomes (target observation, Observatory, lenses); the grade line names the graded host.
  - robots.txt, per-session jars and the cert-retry semantics are in the retriever spec.
  - The timed request offers ALPN `http/1.1` only; ALPN is a separate handshake with no request.
  - `HttpScanner::deadline()` 40s with an inner 35s budget, everything concurrent.
  - Phase 0 has a stop condition and records provenance; the live test uses a fresh `POST /scan`.
  - A missing preload list is visible, never empty.
  - Cheap wins: `url` is already a dependency; the string-matched grade color is the TLS grade; MTA-STS/TLS-RPT read the host only (RFC 8461 §3.4); `txt_at` carries status; RDAP judges name and email separately; security.txt states defined; AC1 path, AC3, AC4, AC5, AC6 corrected; per-phase criteria filled in; `algorithm_version` on the result.
- 2026-10-30: no per-family Observatory grade. Observatory has none, and scan's pinning does not reach redirect targets. Dropped the per-family design and Phase 0d.
- 2026-10-30, panel round 2: both seats confirmed the corrected preload premise (the list is generated at build from Chromium, not checked in). Folded in: an unavailable list scores as "not preloaded" with `preload_available=false`; the lookup rules spelled out and pinned by five fixtures; refresh wording ("attempted after 24h"); the drift risk covers parent and redirect-hop entries; the two risk rows merged; the exact source URL named.
- 2026-10-30: the redirect and cookie views are requested scope: Scott's "add all of that" covered a list naming the `http://` -> `https://` redirect check and cookie flags.

## Alternatives Considered

### Port only the score table
- **Pros:** small.
- **Cons:** cannot reproduce google.com: its redirection and referrer results depend on data scan never collects (the `http://` session, the meta referrer tag).
- **Why not chosen:** Scott's requirement is identical scoring.

### Call the Observatory API instead of porting
- **Pros:** identical by construction.
- **Cons:** a third-party dependency per scan; a 60s cooldown; no per-family result; scan stops probing the host directly.
- **Why not chosen:** scan probes the target itself; the API is the acceptance oracle, not the engine.

### HTML/cookie/structured-field crates (html5ever, cookie, sfv)
- **Pros:** less code.
- **Cons:** different parsers from htmlparser2 and tough-cookie disagree on edge cases; identical scoring needs the same edge cases.
- **Why not chosen:** fidelity.

## Technical Considerations

### Dependencies
- None new expected. reqwest 0.12.24 (`Policy::none`), hickory, tokio-rustls, `regex`, `idna`, `url` (via reqwest), `publicsuffix`. Any crate a phase does need is added with `cargo add`.
- External: the Chromium HSTS list (`raw.githubusercontent.com/chromium/chromium/main/net/http/transport_security_state_static.json`, the URL `retrieve-hsts.js:8` uses), the Observatory API (acceptance only).

### Performance
- Per HTTP scan: two sessions (up to 10 hops each), one preflight, one security.txt GET, one timing probe. Each bounded by 9s/10s timeouts.
- The 10MB preload list is parsed once per refresh and cached on disk; a refresh is attempted after 24h.

### Security
- The cert fallback disables verification only to grade (`verified=false`), as Observatory does; no data from that session is trusted for anything else.
- The preflight sends Observatory's origin; no credentials.

### Testing Strategy
- Ported upstream test vectors; `FakeHttp` extended for headers and methods; a local TLS fake for the probe; `render_pane` per pane; the ignored live test against the API.

### Rollout Plan
- Single repo, ungated. Release through `bump release` after the implementation audit.
- Done means live: `scan --version` shows the released version, AC1-AC6 are re-run against the installed binary, then a tui-test shakedown.
- A grade disputed after release is explained from the live test's provenance output, run on demand.
- MPL-2.0: `LICENSE-MPL-2.0` at the repo root, a header on every derived file (sources, ported tests, fixtures), and the README names `src/scan/observatory/` as MPL-2.0 derived from `mdn/mdn-http-observatory` (no SHA in the README; the source commit lives in the derived files' headers).

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| A site answers Observatory's vantage differently from ripr (consent redirects, geo cookies) | Med | High | Phase 0b drift table; local CLI vs API isolates vantage; exceptions surfaced to Scott |
| The API's preload list (loaded when its analyzer process started) differs from scan's | Low | Med | the result changes only when the host's, a parent's or a redirect hop's entry changed in between; github.com (preloaded) is in the live test; Phase 0b's stop condition catches any unexplained difference |
| Hand-written parsers diverge from htmlparser2/tough-cookie | Med | Med | upstream test vectors ported verbatim; Phase 0c probes tough-cookie |
| Observatory ships algorithm v7 | Low | High | `algorithm_version` recorded on every result; the live test fails loudly on a version mismatch |
| Root store differences (webpki-roots vs Node) change `verified` | Low | Med | invalid-cert results compared in Phase 0b |
| A site varies headers by User-Agent or HTTP version (google.com sends HSTS only to a Firefox UA over HTTP/1.1) | High | High | send Observatory's exact UA and Accept over HTTP/1.1; the live test catches any other request-shape difference |
| Observatory grades the host while a scan target names a path or port | Med | Low | grade the host only and say so; the pane keeps the URL's own results |
| More requests per cycle push HTTP past its timeout | Low | Med | each request has its own 9s timeout; session cap 10s |

## Open Questions
None.

## Review Pass Log
- Pass 1 (draft): defect table from the v0.5.8 shakedown, Observatory algorithm from the source read at `2776308`, lenses from the seed; 8 phases.
- Pass 2 (correctness): measured that google.com sends HSTS only to a Firefox UA over HTTP/1.1, which reverses the earlier "Missing HSTS is correct" call and makes the request shape part of the port; result names verbatim from `charts.js`; `url` needs `cargo add` to be used directly; TTL criterion made exact.
- Pass 3 (clarity): the live test's host list named; AC5 written as a literal command.
- Pass 4 (edge cases): IP targets and dotless names get `Grade: n/a`, never F (Observatory refuses them); URL targets grade the host only; site-down and unexpected-status read `Grade: none`; two risks added.
- Pass 5 (excellence): every acceptance criterion run against installed v0.5.8; all fail there as they should.
- Panel round 1: see Resolved Decisions. Acceptance criteria rewritten and re-run on main.
- Panel round 2 (the preload dispute): see Resolved Decisions.
- Re-ran AC1-AC6 on main: AC5 passes, which showed item 5 is bounded retention (+140 KB from 660s to 900s), not a leak. Item 5, Phase 0a and Phase 2 rewritten; AC5 kept as a regression guard.

## References
- `docs/design/2026-10-29-shakedown-v0.5.7-fixes.md`
- `mdn/mdn-http-observatory` @ `2776308` (`src/scanner/index.js`, `src/grader/charts.js`, `src/retriever/*`, `src/analyzer/tests/*`)
- RFC 9116 (security.txt), RFC 8461 (MTA-STS), RFC 8460 (TLS-RPT), RFC 9537 (RDAP redaction), RFC 8941 (structured fields)
