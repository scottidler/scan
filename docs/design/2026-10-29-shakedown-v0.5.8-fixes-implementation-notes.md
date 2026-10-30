# Implementation Notes: Shakedown Fixes After v0.5.8, Observatory Grading, and New Target Lenses

Design doc: `docs/design/2026-10-29-shakedown-v0.5.8-fixes.md`

## Phase 0: Spikes

All measurements on ripr (64 cores, no IPv6 default route), 2026-10-30, against main `d91a6e7`
(code identical to `38aa3bf`) and the installed `scan v0.5.8`. Harnesses lived in the session
scratchpad and are not committed; the recipes are below.

### 0a: DnsResult memory

Method: a temporary `#[ignore]` test inside `src/scan/dns.rs`, in a scratch worktree (the
function is private), with a counting `#[global_allocator]`. It called `perform_dns_lookup` for
`google.com` (`Protocol::Both`) 12 times on one `DnsScanner`, kept every result (as the history
does), and recorded per call: net live bytes after the call settled (500 ms), peak live bytes
during the call, allocation count, bytes allocated, a deep heap walk of the result (every `Vec`
and `String` capacity), and the `{:?}` length.

Per call (calls 1..11 identical within a few bytes; call 0 adds first-call init):

```
size_of::<DnsResult>() inline = 576 bytes
size_of::<ScanResult>() inline = 1360 bytes
call 0: retained_live_delta=11899 B peak_during_call=2244100 B allocs=64879 bytes_allocated=4461353 deep_heap=5676 B debug_len=5799 B
call 1: retained_live_delta=5676 B peak_during_call=2235685 B allocs=64849 bytes_allocated=4452675 deep_heap=5676 B debug_len=5799 B
call 11: retained_live_delta=5676 B peak_during_call=2237877 B allocs=64855 bytes_allocated=4454867 deep_heap=5676 B debug_len=5799 B
dropping 12 retained results freed 77328 B
```

Largest fields of one result (heap bytes):

| Field | Records | Heap |
|---|---|---|
| TXT | 17 | 2463 B |
| `*_status` (`QueryStatus::Failed` message strings) | - | 1600 B |
| SOA | 1 | 432 B |
| CAA | 1 | 336 B |
| NS | 4 | 256 B |
| MX | 1 | 240 B |
| AAAA | 1 | 160 B |
| A | 1 | 96 B |
| email_security | - | 93 B |
| CNAME, PTR, SRV | 0 | 0 B |

The transient cost per call is the public suffix list. `SuffixList::registrable_domain` alone,
3 calls:

```
registrable_domain alone: Ok(Some("google.com")) peak=2120584 B allocs=62027 bytes_allocated=3650513 retained=10 B
```

`lookup_dmarc` calls it on every DNS cycle, and `CachedSource::load` re-reads and re-parses
`~/.cache/scan/public_suffix_list.dat` (338012 B) each time: 95% of the call's peak, 96% of its
allocations, 82% of its allocated bytes. None of it is retained.

RSS, `scan --no-tui google.com` (installed v0.5.8), sampled with `ps -o rss=`, killed at 900 s.
Second column is the same run with `MALLOC_ARENA_MAX=1`, started 36 s later:

| t (s) | RSS KB (default) | RSS KB (`MALLOC_ARENA_MAX=1`) |
|---|---|---|
| 20 | 21800 | 19624 |
| 60 | 21828 | 19700 |
| 120 | 24340 | 19780 |
| 180 | 24380 | 19860 |
| 240 | 26368 | 19924 |
| 300 | 26596 | 20008 |
| 360 | 28744 | 20088 |
| 420 | 28752 | 20168 |
| 480 | 28768 | 20180 |
| 540 | 28840 | 20252 |
| 600 | 28948 | 20328 |
| 660 | 28940 | 20292 |
| 720 | 29004 | 20340 |
| 780 | 29004 | 20416 |
| 840 | 29032 | 20432 |
| 900 | 29156 | 20468 |

Plateau: 660 s 28940 KB, 900 s 29156 KB, +216 KB (AC5's command shape would print 216; < 1024,
passes).

Verdict: item 5's premise is refuted. One retained `DnsResult` is 5676 B of heap plus 576 B
inline (6444 B per history entry as measured by the drop), so the 10-deep history holds about
64 KB, not ~10 MB. Every byte is record data the DNS pane shows (TXT, SOA, CAA, NS, MX, A, AAAA,
the SPF/DMARC strings) or status text. Per the doc's rule, **Phase 2 is skipped**. The RSS climb
is glibc malloc arenas, not retained results: it rises in ~2 MB steps at 120, 240 and 360 s (new
worker threads on a 64-core host each taking an arena for the 2.2 MB transient peak), and with
one arena the same 900 s run grows 844 KB in total.

### 0b: Observatory oracle

Setup: `npm ci` in `~/repos/mdn/mdn-http-observatory` at `2776308` ran inside the sandbox
without trouble. Its postinstall wrote `conf/hsts-preload.json` from Chromium `main` at
2026-10-30 00:44 PDT: 13988172 bytes, 95542 entries, sha256
`01bb069660508ccabf0d1faa52cd0ffccd97fb5751da7d7ed63c288cd1c958a2`. `github.com` is in it
(`force-https`, `includeSubDomains: true`). The other five hosts are not.

Per host, four things started in parallel in the same second, then `GET /api/v2/analyze`:

- the local CLI as shipped (`node bin/wrapper.js <host>`);
- the local CLI with production's CA setup (`node src/scan.js`, see the example.com row);
- a capture harness: Observatory's own `retrieve()` + `analyzeScan()`, with every HTTP exchange
  recorded through `diagnostics_channel` `http.client.response.finish` (request bytes, status,
  raw response headers);
- `POST /api/v2/scan?host=<host>`.

The API's 60 s cooldown was respected, so every POST was a fresh scan. In every row below the
analyze response carries the POST's scan id. Local Node is v26.10.0; production runs `node:24`
(`Dockerfile`).

Final run (`runs3`), 2026-10-30:

| Host | API scan id | API `scanned_at` | API | Local CLI (shipped) | Local CLI (prod CA) | Capture | Effective URL (auto) | verified | Verdict |
|---|---|---|---|---|---|---|---|---|---|
| google.com | 132240279 | 08:02:23.956Z | C- 45 | C- 45 | C- 45 | C- 45 | `https://google.com/` -> `https://www.google.com/` | true | identical |
| www.tatari.tv | 132240596 | 08:03:28.962Z | B 75 | B 75 | B 75 | B 75 | `https://www.tatari.tv/` | true | identical |
| github.com | 132240623 | 08:03:36.307Z | A+ 115 | A+ 115 | A+ 115 | A+ 115 | `https://github.com/` | true | identical |
| example.com | 132240684 | 08:03:55.166Z | F 10 | F 10, 1 test differs | F 10 | F 10 | `https://example.com/` | true (prod CA) / false (shipped) | explained (1) |
| mozilla.org | 132240791 | 08:04:25.681Z | B+ 80 | B+ 80 | B+ 80 | B+ 80 | `https://mozilla.org/` -> `https://www.mozilla.org/` | true | identical |
| neverssl.com | 132239430 (run nev5, 07:59:19.732Z) | | D 30 | D 30 | | (site down) | `https://neverssl.com/` | true | identical in nev5; explained (2) |

"Identical" means all 12 `result` strings, every `score_modifier`, the score, the grade and
`algorithm_version` 6. Earlier runs (`runs2`, 07:49-07:51Z) gave the same grades and results for
the five stable hosts.

Per-test API results (runs3; nev5 for neverssl.com):

| Test | google.com | www.tatari.tv | github.com | example.com | mozilla.org | neverssl.com |
|---|---|---|---|---|---|---|
| content-security-policy | not-implemented-but-reporting-enabled -25 | not-implemented -25 | unsafe-inline-in-style-src-only 0 | not-implemented -25 | unsafe-inline -20 | not-implemented -25 |
| cookies | without-secure-flag-but-protected-by-hsts -5 | not-found 0 | secure-with-httponly-sessions-and-samesite +5 | not-found 0 | not-found 0 | not-found 0 |
| cross-origin-embedder-policy | not-implemented 0 | not-implemented 0 | not-implemented 0 | not-implemented 0 | not-implemented 0 | not-implemented 0 |
| cross-origin-opener-policy | same-origin-allow-popups +10 | not-implemented 0 | not-implemented 0 | not-implemented 0 | same-origin +10 | not-implemented 0 |
| cross-origin-resource-policy | not-implemented 0 | not-implemented 0 | not-implemented 0 | not-implemented 0 | not-implemented 0 | not-implemented 0 |
| cross-origin-resource-sharing | not-implemented 0 | not-implemented 0 | not-implemented 0 | not-implemented 0 | not-implemented 0 | not-implemented 0 |
| redirection | not-to-https-on-initial-redirection -10 | to-https 0 | all-redirects-preloaded 0 | missing -20 | to-https 0 | not-needed-no-http 0 |
| referrer-policy | unsafe -5 | not-implemented 0 | private +5 | not-implemented 0 | private +5 | not-implemented 0 |
| strict-transport-security | implemented-max-age-at-least-six-months 0 | at-least-six-months 0 | preloaded +5 | not-implemented -20 | at-least-six-months 0 | not-implemented -20 |
| subresource-integrity | not-implemented-but-external-scripts-loaded-securely -5 | all-scripts-from-secure-origin 0 | external-scripts-loaded-securely -5 | all-scripts-from-secure-origin 0 | all-scripts-from-secure-origin 0 | all-scripts-from-secure-origin 0 |
| x-content-type-options | not-implemented -5 | nosniff 0 | nosniff 0 | not-implemented -5 | nosniff 0 | not-implemented -5 |
| x-frame-options | sameorigin-or-deny +5 | sameorigin-or-deny +5 | implemented-via-csp +5 | not-implemented -20 | implemented-via-csp +5 | not-implemented -20 |

Short names; the API and the fixture carry the full strings (e.g. `csp-not-implemented-but-reporting-enabled`).

Redirect routes the capture recorded (status of each hop's response):

- google.com http: `301 http://google.com/`, `302 http://www.google.com/`, `200 https://www.google.com/?gws_rd=ssl`; https: `301 https://google.com/`, `200 https://www.google.com/`.
- www.tatari.tv http: `308 http://www.tatari.tv/`, `200 https://www.tatari.tv/`; https: `200 https://www.tatari.tv/`.
- github.com http: `301 http://github.com/`, `200 https://github.com/`; https: `200 https://github.com/`.
- example.com http: `200 http://example.com/`; https: `200 https://example.com/`.
- mozilla.org http: `302 http://mozilla.org/`, `301 https://mozilla.org/`, `200 https://www.mozilla.org/`; https: `301 https://mozilla.org/`, `200 https://www.mozilla.org/`.

Request headers the CLI sent (google.com, verbatim apart from cookie values):

```
GET / HTTP/1.1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:129.0) Gecko/20100101 Firefox/129.0 Observatory/129.0
Accept-Encoding: gzip, compress, deflate, br
Host: google.com
Connection: close
```

- Session requests (both sessions, every redirect hop) send `Connection: close`. Later hops carry
  `Cookie:` from that session's jar.
- robots.txt (`Accept: text/plain,*/*;q=0.8`) and the preflight go through the auxiliary client
  with `Connection: keep-alive`. On the normal path neither sends a `Cookie:`.
- The preflight adds `Access-Control-Request-Method: GET` and
  `Origin: https://http-observatory.security.mozilla.org`.
- `Accept-Encoding: gzip, compress, deflate, br` is axios's default and is not in the design doc.
  google.com answers `Content-Encoding: br`, so the port must decode brotli or send a header the
  site answers differently to.

Explained differences:

1. **example.com, shipped CLI only:** `hsts-invalid-cert` locally vs `hsts-not-implemented` on the
   API. `bin/wrapper.js` sets `NODE_EXTRA_CA_CERTS` to the intermediates-only
   `ca_intermediate_bundle.pem`. With it, Node fails example.com's chain (leaf -> Cloudflare TLS
   Issuing ECC CA 3 -> SSL.com TLS Transit ECC CA R2 -> SSL.com TLS ECC Root CA 2022) with
   `UNABLE_TO_GET_ISSUER_CERT`. With no extra certs, or with `ca_intermediate_root_bundle.pem`,
   it verifies (`authorized true`). Production's `Dockerfile` sets
   `NODE_EXTRA_CA_CERTS=node_modules/extra_certs/ca_bundle/ca_intermediate_bundle.pem`. That path
   does not exist (the package is `node_extra_ca_certs_mozilla_bundle`), so Node logs
   `Warning: Ignoring extra certs ... No such file or directory` and production verifies against
   Node's bundled roots only. Run that way locally, example.com is identical to the API. Production
   wins: scan verifies against a standard root store with no extra intermediates.
2. **neverssl.com:** the host flaps on both ports from ripr. `curl -4 http://neverssl.com/` 6
   times: 200 after an 11.2 s connect, then timeout, 200 (2.07 s connect), timeout, 200 (2.05 s),
   timeout. `https://` connects in 10 ms but mostly gets `Empty reply from server` after 5 s.
   So which sessions exist differs per run, from either vantage. Three outcomes appear on both
   sides:
   - only http answers: F 10 (`redirection-missing`, `hsts-not-implemented-no-https`);
   - only https answers: D 30 (`redirection-not-needed-no-http`, `hsts-not-implemented`);
   - neither answers: `The site seems to be down.`

   Runs nev1-nev4: the API said site down, the local CLI gave F 10, site down, site down, D 30.
   Run nev5 graded on both sides at the same time: D 30 = D 30, all 12 identical. runs3: both
   site down. The API's previous stored scan (id 132084385, 2026-10-29T19:47:54Z) is D 30 with
   nev5's results. The captured inputs (which sessions answered) explain every difference. The
   host makes a single-shot live comparison non-deterministic (Open questions).
3. **`pass`:** the API returns `pass: null` where the CLI says `true` for
   `referrer-policy-not-implemented`, `sri-not-implemented-response-not-html`,
   `sri-not-implemented-but-no-scripts-loaded`,
   `sri-not-implemented-but-all-scripts-loaded-from-secure-origin`, `cookies-not-found` and
   `corp-not-implemented`. `hydrateTests` (`src/api/v2/utils.js:211-242`) does this for display
   only. Results and modifiers are untouched.

Stop condition: not triggered. Every difference is explained by a captured input. No host was
moved off the list.

Other facts the port needs, measured here:

- A non-2xx preflight answer gives `responses.cors = null`, because the auxiliary axios client
  keeps the default `validateStatus` (2xx only), throws, and `Session.options` returns null. Seen
  for google.com 405, www.tatari.tv 400, github.com 404, example.com 405. Only mozilla.org (200)
  had a CORS response.
- The API's `GET /api/v2/analyze?host=google.com` took 15-60 s and once returned HTTP 503 after
  63 s with an empty body: the response carries the site's history (290824 bytes). The Phase 6
  live test needs a long timeout and a retry on 5xx.
- The CLI refuses a dotless hostname itself (`Site.fromSiteString`, `src/site.js:108-114`:
  `localhost is invalid: hostname must have at least a host and TLD`), not only the API.

#### Fixture for Phase 4

`tests/fixtures/observatory/google-com.json` (260667 bytes), from the runs3 google.com capture
(API scan 132240279). It contains:

- `responses.http`, `responses.https`, `responses.cors` (null here): url, status, `verified`,
  axios's merged `headers`, `raw_headers` (Node's `rawHeaders`, duplicates and order preserved),
  `request_raw`, body.
- `responses.auto`: `same_as: "https"` plus its `http_equiv` map (`referrer-policy: ["origin"]`
  from the meta tag, an empty CSP list).
- Both redirect routes, `auto_session` and `auto_session_url`.
- The auto session's jar (`CookieJar.serializeSync()`).
- `wire`: every exchange, including robots.txt and the preflight, each with request bytes and
  raw response headers.
- `observatory_cli_result` (Observatory's `analyzeScan` on these inputs).
- `api_result` (the API's scan summary and all 12 `{result, score_modifier, pass}`).
- `_provenance`.

The http session's body was dropped (`data: null`, `data_length` kept) because no analyzer reads
it. The auto body (217548 chars, brotli-decoded) is kept whole for SRI and meta parsing. Cookie
values are replaced by `REDACTED` in `Set-Cookie`, `Cookie` and the jar. No analyzer reads a
cookie value: `cookies.js` reads keys and attributes, and its 32768 size check joins objects.

Proof the fixture is complete: a replay script rebuilt Observatory's `Requests` from the fixture
alone and ran `analyzeScan`. It printed `google.com replay C- 45 api C- 45 IDENTICAL`, with all
12 results and modifiers equal. It still printed that after the `__Secure-STRP` cookie in the jar
expired (see 0c ii), so the fixture does not depend on when it is replayed.

Re-capture recipe (the scripts died with the session scratchpad):

1. In `~/repos/mdn/mdn-http-observatory` at `2776308`, run `npm ci`.
2. Run an ESM script with `NODE_EXTRA_CA_CERTS` set to a path that does not exist, to match
   production. The script imports `src/retriever/retriever.js` `retrieve`,
   `src/scanner/index.js` `analyzeScan` and `src/site.js` `Site`, and subscribes to
   `diagnostics_channel` `http.client.response.finish`, recording `request.method`,
   `request.protocol`, `request.host`, `request.path`, `request._header`,
   `response.statusCode` and `response.rawHeaders`.
3. `const req = await retrieve(Site.fromSiteString(host), {})`.
4. Serialize `req.responses.{http,https,auto,cors}` (`status`, `verified`, `headers.toJSON()`,
   `request.res.rawHeaders`, `request._header`, `data`, `httpEquiv`), the redirect histories, and
   `req.session.jar.serializeSync()`.
5. Run `analyzeScan(req)`.
6. In the same second, `POST https://observatory-api.mdn.mozilla.net/api/v2/scan?host=<host>`,
   then `GET /api/v2/analyze?host=<host>` with a long timeout. Check that `scan.id` matches the
   POST.
7. Redact cookie values as above.

### 0c: quirks

**(i) CORS universal access: proven dead in production.**

- `httpbin.org` answers the preflight with
  `access-control-allow-origin: https://http-observatory.security.mozilla.org` and
  `access-control-allow-credentials: true` (`quirk1` capture, raw headers recorded).
- API scan 132239764 (2026-10-30T08:00:32.254Z) and the local CLI (both CA setups) all graded
  `cross-origin-resource-sharing-implemented-with-restricted-access` (0), data
  `https://http-observatory.security.mozilla.org`. All 12 tests matched, F 15 on all three.
- Cause: `cors.js` reads the request's Origin through `getFirstHttpHeader(response.request, ...)`,
  which reads `response.request.headers`. `response.request` is Node's `ClientRequest`, and that
  has no `headers` property: `ClientRequest.headers = undefined` on Node v26.10.0, while
  `getHeader("origin")` returns the value. So `originHeader` is always null.
- The universal-access result cannot occur, and an echoed origin with credentials is
  restricted-access. The port reproduces that, as production does.

**(ii) Already-expired `Set-Cookie`: kept, and graded.** A local server
(`http://cookie.test.localhost:18431/`, resolved to 127.0.0.1 by the system resolver) answered:

- `/` with a 302 to `/final`, setting `hop1=1` and `deleted-later=1`;
- `/final` with a 200 and the cookies below.

The local CLI's jar (`serializeSync`):

| Set-Cookie on `/final` | In jar | Stored as |
|---|---|---|
| `expired-1970=1; Expires=Thu, 01 Jan 1970 00:00:00 GMT` | yes | `expires 1970-01-01T00:00:00.000Z` |
| `expired-recent=1; Expires=Wed, 29 Oct 2025 00:00:00 GMT` | yes | `expires 2025-10-29T00:00:00.000Z` |
| `maxage-zero=1; Max-Age=0` | yes | `maxAge 0` |
| `maxage-negative=1; Max-Age=-1` | yes | `maxAge -1` |
| `deleted-later=; Expires=Thu, 01 Jan 1970 ...` (after `deleted-later=1` on the 302) | yes, replaced | empty value, `expires 1970` |

- tough-cookie 5.1.2 stores expired cookies.
- `serializeSync()`, which `cookies.js:93-95` reads, returns them.
- `getCookiesSync(url)` drops them. Confirmed on the google fixture: after `__Secure-STRP`
  expired, `serializeSync` listed `__Secure-STRP,SEARCH_SAMESITE,AEC,NID` and `getCookiesSync`
  listed `SEARCH_SAMESITE,AEC,NID`.
- The cookies test therefore grades expired and deleted cookies like live ones. The CLI's cookies
  `data` listed all 14 keys, and the result was `cookies-session-without-secure-flag`.
- The port's jar keeps every accepted cookie whatever its expiry. Only replacement by name,
  domain and path removes an entry.

**(iii) Cross-domain `Set-Cookie`: rejected silently.** `http-cookie-agent` 8.0.0 calls
`jar.setCookieSync(cookie, url, { ignoreError: true })`, so a rejected cookie disappears without
error. Request host `cookie.test.localhost`:

| Set-Cookie | In jar |
|---|---|
| `xdomain=1; Domain=example.com` | no |
| `xdomain-dot=1; Domain=.example.com` | no |
| `parent-domain=1; Domain=test.localhost` | yes, `domain test.localhost`, `hostOnly false` |
| `tld-domain=1; Domain=localhost` | yes, `domain localhost`, `hostOnly false` (tough-cookie allows special-use names) |
| `host-domain=1; Domain=cookie.test.localhost` | yes, `hostOnly false` |

A public suffix as `Domain=` (e.g. `Domain=com` from a `.com` host) was not tested: that needs a
public name served locally.

Also measured on the same server:

- `secure-over-http=1; Secure`, `__Secure-prefixed=1; Secure` and `__Host-prefixed=1; Secure`
  set over plain `http://` are all kept with `secure: true`. tough-cookie enforces neither a
  secure origin nor the prefixes here.
- The jar's cookies went out on the redirect hop (`GET /final` carried
  `Cookie: hop1=1; deleted-later=1`).
- robots.txt's `Set-Cookie: robots=1` did not reach the jar on the normal (verified) path, and
  neither robots.txt nor the preflight sent a `Cookie:`. This matches the doc's retriever spec.

### Design decisions

- The Phase 4 fixture lives at `tests/fixtures/observatory/google-com.json`, outside `docs/`, as
  a JSON capture. Phase 4 can `include_str!` it. It is captured site data plus Observatory
  output, not Observatory source, so it carries a `_provenance` block instead of an MPL-2.0
  header (JSON has no comments). Phase 4 decides whether its port of the file needs the header.
- The capture ran with production's CA setup (no extra certs), not the shipped wrapper's,
  because production wins (Resolved Decisions, 2026-10-29), and example.com shows the two
  differ.
- Cookie values are redacted in the fixture. They are Google's anonymous tracking cookies,
  nothing of ours, but no analyzer reads them and a fixture has no reason to carry them.
- 0a verdict per the doc's rule: no unread data in `DnsResult`, so Phase 2 is skipped. The
  measured cause of the RSS climb is recorded here rather than fixed, because Phase 2's scope is
  data held in the result.

### Deviations

- 0a "serialize-size": `DnsResult` has no `Serialize`. It was measured three ways instead:
  `{:?}` length (5799 B), a deep heap walk (5676 B), and a counting allocator's retained delta
  (5676 B). Same intent: the three agree on the order of magnitude, and the latter two agree to
  the byte.
- 0a ran as a temporary `#[ignore]` test in a scratch git worktree (removed afterwards), since
  `perform_dns_lookup` is private. No scan code was committed.
- 0b added a fourth runner per host, the local CLI with production's CA setup, beyond the doc's
  "local CLI". It exists because example.com's shipped-CLI result differs from production for a
  reason outside the scanned site.
- 0b's capture harness is a second retrieval in the same second as the CLI, not the CLI process
  itself. In runs2 and runs3 its 12 results equalled the CLI's for every host that graded.
- neverssl.com's same-minute comparison that graded on both sides is run nev5 (07:59Z), not the
  final runs3 batch, where both sides reported the site down.

### Tradeoffs

- Full auto body (217548 chars) in the fixture vs a trimmed one: SRI and meta parsing read the
  whole document, and a trimmed body would no longer be what the API graded. The other session's
  body is dropped, since nothing reads it.
- A replay-validated fixture vs trusting the capture: a JS replay through Observatory's own
  `analyzeScan` proves the fixture holds every input before Phase 4 builds on it.
- Recipe in the notes vs a committed capture tool: Phase 6's live test is the durable oracle, so
  a Node tool in a Rust repo would duplicate it. The recipe is enough to re-capture by hand.

### Open questions

- **neverssl.com in the live test:** its ports 80 and 443 flap from ripr and from the API's
  vantage. Over 7 same-minute runs the API graded it once and the local CLI three times, with two
  different grades (F 10 / D 30) depending on which port answered. A single-shot
  `scan_matches_the_live_observatory_api` will fail on it intermittently with both sides correct.
  The doc says a host leaves the list only by a dated Resolved Decision with Scott's say-so. Keep
  it with a retry and an "both sides site-down is a match" rule, replace it with another
  plain-HTTP host, or drop it?
- **Suffix-list re-parse per DNS cycle:** each DNS scan re-reads and re-parses the 338 KB public
  suffix list (2.1 MB transient peak, 62027 allocations, 3.65 MB allocated). The cycle can be as
  short as 10 s, and on a 64-core host this transient load is what grows glibc arenas (+7140 KB
  RSS by 660 s). It is not item 5 as written and not Phase 2's scope (data in `DnsResult`).
  Should keeping the parsed list in memory become a tracked item?
- **Item 5 text in the design doc:** "Each retained DNS result costs ~1 MB" is refuted (6444 B).
  The parent or Scott decides whether the doc's Problem table gets a correction note.
