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

## Phase 1: Shakedown correctness fixes

Items 1, 2, 3, 4, 6, 7. Item 5 untouched (Phase 2 skipped per 0a).

### Design decisions

- `DNS_REQUERY_GRACE` (1s) is added to the earliest expiry before the 10s..60s clamp: `src/scan/dns.rs:DnsResult::requery_delay`: the clamp still bounds the final delay, so 4s -> 10s, 30s -> 31s, 300s -> 60s.
- `ttl_span` takes a `refreshing` flag computed once from the DNS `ScanState` (`status == Running`) and threaded through `build_dns_result_lines`, `record_line` and `ptr_lines`: `src/tui/dns.rs`: the label is a fact about the scanner, not the record, so the caller that holds the scanner state decides it. Idle 0 reads `expired`, MUTED.
- PTR classification moved into two pure functions, `ptr_answer` (one lookup -> `Names`/`Empty`/`Failed`) and `ptr_records_and_status` (all answers -> records + `QueryStatus`): `src/scan/dns.rs`: so the no-records rule is testable without a resolver. `is_empty_answer` is shared with `timed_lookup`, so forward and reverse lookups cannot drift apart again.
- `PTR: none` (MUTED) is a PTR-only override of `status_display`'s `NoRecords`: `src/tui/dns.rs:ptr_lines`: the other record types keep `No Records` (cosmetic items are Phase 3).
- The chain is `presented_chain(leaf, chain)`: the peer chain when non-empty, the leaf alone otherwise: `src/scan/tls.rs`: generic over the certificate type so both branches are unit-tested without a handshake. The 3-certificate case is also tested end to end against a loopback OpenSSL server sending leaf + 2 extra chain certs (`fixtures::spawn_loopback_tls_server_with_intermediates`).
- `ContactInfo.is_redacted: bool` is replaced by `redacted: Vec<ContactField>`: `src/scan/whois.rs`: per-field redaction is what RFC 9537 expresses, and a separate whole-contact bool would encode the same fact twice. A `REDACTED FOR PRIVACY` remark becomes `ContactInfo::fully_redacted()` (every field). `ContactInfo::visible(field)` is the one accessor that hides withheld values.
- RFC 9537: `rdap_redactions` reads `redacted[].name.description` (or `name.type`), `redaction_target` maps `<Role> <Field>` names (Registrant/Admin/Administrative/Tech/Technical; Name, Organization, Email, Phone/Fax(+Ext), Street/City/Postal Code/State/Province/Country/Address). Billing and registry IDs are ignored with a trace log, since scan stores no billing contact. `apply_redactions` creates the contact when the registry withheld everything that would have made `parse_contact_info` return one.
- Every empty vCard value (`fn`, `org`, `email`, `tel`) is `None`, not only `fn`: `parse_contact_info`: the same `Some("")` bug applies to each.
- `PrivacyLevel::Partial` ("partial (some contact fields visible)", WARN) is new: name and email judged separately; both visible `Open`, one `Partial`; neither: visible org `Corporate`, any redaction `Protected`, else `Unknown`.
- Zoom: a fully withheld contact keeps the one-line `<Role> (redacted)` header; a partly withheld one prints `<Field>: (redacted)` per withheld field: `src/tui/whois.rs:contact_lines`.
- HTTP: the placeholder branch is skipped when the scanner is `Failed` or has an `error` (retrying): `src/tui/http.rs`. The `💻 Server: detecting...` row is deleted. First-run placeholders (`checking...`, `measuring...`) stay.
- Target: `address_line` reads only `state.resolved_ips` (main's `Target::resolve`, the system resolver the scanners use); a missing family reads `none` (MUTED), `n/a` for an IP literal. `address_from_dns` is deleted: `src/tui/target.rs`.

### Deviations

- Item 7's old DNS fallback was also what turned a failed AAAA query into a red `❌ IPv6: no data` on the Target row. With one source, that row reads `none`; the DNS failure still shows in the DNS pane. The pinning tests were inverted by name, not deleted: `dns_records_fill_in_when_resolution_has_no_address` -> `dns_records_never_stand_in_for_resolution`, `queried_family_that_errored_stays_red` -> `dns_query_error_does_not_paint_the_address_row`, `domain_with_empty_aaaa_shows_neutral_none` -> `domain_without_an_ipv6_address_shows_neutral_none` (now driven by `resolved_ips`).
- Item 1's old `ttl_reads_cached_and_expired_reads_refreshing` pinned `expired, refreshing` on a `Complete` scanner; inverted as `ttl_reads_cached_and_expired_reads_refreshing_only_while_running`. `requery_delay_is_the_earliest_expiry_clamped_to_10s_60s` became `requery_delay_is_one_second_past_the_earliest_expiry_clamped_to_10s_60s` (30s -> 31s); the cross-type test's 25s became 26s and `next_delay`'s window 30..31s.
- `QueryStatus` gained `PartialEq, Eq` so the PTR tests compare statuses directly. Same effect, no behavior change.
- The chain criterion says "renders `3 certificates`": verified by rendering the zoomed Security pane from the TLS scan of the loopback fixture, not from a hand-built `TlsData`, so the count comes from OpenSSL's `peer_cert_chain()` on a live handshake.

### Tradeoffs

- Per-field `Vec<ContactField>` vs keeping `is_redacted` and adding a field list: one signal, and `fully_redacted()` keeps the remark case a one-liner.
- A loopback TLS server for the chain vs only the pure `presented_chain` test: the pure test covers the no-chain branch (a resumed session cannot be produced cheaply), the loopback test proves the client-side chain includes the leaf.
- `PtrAnswer` enum + pure status function vs testing `reverse_lookup` live: no network, and a hickory `ResolveError` for NOERROR-empty and NXDOMAIN is built with `ProtoError::nx_error`.

### Bite proofs

Each fix undone in turn (scripted string mutation of the working tree, `cargo test --lib <filter>`, restore), with the tests it broke:

| Fix undone | Failing tests |
|---|---|
| 1: `expiry + DNS_REQUERY_GRACE` -> `expiry` | `requery_delay_is_one_second_past_the_earliest_expiry_clamped_to_10s_60s`, `requery_delay_takes_the_earliest_record_across_types` |
| 1: `ttl_span` always `expired, refreshing` | `ttl_reads_cached_and_expired_reads_refreshing_only_while_running` |
| 2: PTR `is_empty_answer` arm removed | `ptr_without_a_record_is_no_records_never_failed` |
| 2: PTR `none` render arm removed | `ptr_without_a_record_reads_none_and_an_error_reads_failed` |
| 3: leaf pushed before the peer chain (old code) | `chain_of_leaf_and_two_intermediates_counts_three_certificates` (got 4), `presented_chain_is_the_peer_chain_and_the_leaf_only_without_one` |
| 4: empty-value filter removed | `empty_fn_with_visible_email_is_partial` |
| 4: `apply_redactions` call removed | `rfc9537_name_redaction_with_visible_email_is_partial`, `rfc9537_full_redaction_is_protected` |
| 4: one visible field -> `Open` (old one-flag rule) | `empty_fn_with_visible_email_is_partial`, `rfc9537_name_redaction_with_visible_email_is_partial` |
| 4: per-field `(redacted)` row removed | `zoom_marks_each_withheld_field_redacted` |
| 6: `\|\| http_state.error.is_some()` removed | `retrying_after_a_failure_shows_no_placeholders` |
| 7: DNS records fallback restored | `dns_records_never_stand_in_for_resolution`, `localhost_rows_equal_the_scanners_resolution_not_hickory` |

`first_run_shows_placeholders_but_no_server_row` asserts the deleted `Server:` row is absent; it was not mutation-run (re-adding the row is the only undo).

### Open questions

- `PrivacyLevel::Partial`'s label is `partial (some contact fields visible)`. AC4 only requires `Privacy: ` present and not `open`; Scott may want different wording.
- With the DNS fallback gone, a domain whose `resolved_ips` is empty would read `none` on both rows. `main` fails before the TUI when resolution errors, so this is not reachable today; noted in case a later phase re-resolves on protocol change.

## Phase 3: Cosmetic fixes
### Design decisions
- Protocol joins the Status row as `Status: <counts> · IPv4+IPv6 (p)` and the `Protocol:` row is deleted: `src/tui/target.rs:content`. 12 content rows at 200x55 (4 + 8 scanners), so `↓ 1 more` is gone.
- `plural(n, noun)` returns `"<n> <noun>"` with an `s` unless n is 1: `src/tui/text.rs`. Used for DNS `status_display`, CNAME/NS/TXT/MX/SRV headers, Security SAN, WHOIS risks, Ports `Open:` and the `--no-tui` WHOIS `risks` suffix. The count is part of the string, so call sites no longer format the number separately.
- One `status_header(label, status, first_ttl, refreshing)` builds the A and AAAA headers with TTL inline (`, TTL: <ttl>`), the shape PTR and the other sections already had: `src/tui/dns.rs`.
- A and AAAA are skipped when `is_reverse_only()` (IP target): `src/tui/dns.rs:build_dns_result_lines`.
- Ports: the `Scanned:` row is deleted outright, so row count no longer depends on scan status (items 11 and 12 share one fix): `src/tui/ports.rs`.
- Security: the `🔗 Status: failed` row in the first-scan-failed branch is deleted; the header's `Status: failed: <error>` stands alone: `src/tui/security.rs`. The `connection_successful == false` row inside a completed result is a different fact and stays.
- `pretty.rs` reads `, N no reply`, matching the TUI traceroute pane's wording: `src/pretty.rs`.

### Deviations
- The two protocol-row tests (`protocol_line_is_fit_with_ellipsis_at_108_columns`, `protocol_line_that_fits_is_unchanged`) were replaced by `target_at_200x55_shows_every_row_and_the_protocol_on_the_status_row`: they pinned the deleted `Protocol:` row. Truncation of a long row is still covered by `fit_line` and `long_target_is_fit_with_ellipsis_in_narrow_terminals`.
- `layout.rs` `dns_fixture` and one DNS test fixture now set `MX_status = NoRecords`. With A/AAAA hidden for IP targets, a fixture without a queried MX reads as an IP target and lost its rows; real name targets always query MX.
- `Open: N ports` in the Ports pane and the `--no-tui` WHOIS `N risks` were also routed through `plural` (the doc says "every count"); not named in the defect table.

### Tradeoffs
- `plural` appends `s` only vs an irregular-noun table: every noun used is regular; a table is speculative.
- Delete `Scanned:` vs keep it in both states: it duplicated the Status row, so deleting fixes items 11 and 12 together.

### Bite proofs
Each fix undone in turn (scripted string mutation, `cargo test --lib <filter>`, restore):

| Fix undone | Failing tests |
|---|---|
| 8: protocol dropped from Status row | `target_at_200x55_shows_every_row_and_the_protocol_on_the_status_row` |
| 8: `Protocol:` row restored | `target_at_200x55_shows_every_row_and_the_protocol_on_the_status_row`, `short_pane_shows_the_summary_and_marks_the_hidden_scanners` |
| 9: `plural` always adds `s` | `plural_adds_an_s_unless_the_count_is_one`, `a_count_of_one_reads_in_the_singular`, `san_count_of_one_reads_domain`, `one_risk_indicator_reads_in_the_singular`, `one_open_port_reads_in_the_singular`, `cname_and_caa_render_their_sections` |
| 9: WHOIS `indicators` unpluralized | `one_risk_indicator_reads_in_the_singular` |
| 10: A/AAAA header without inline TTL | `every_section_header_carries_its_ttl_inline`, `a_count_of_one_reads_in_the_singular` |
| 10: A/AAAA shown for an IP target | `ip_target_renders_no_a_or_aaaa_row` |
| 11: `Scanned:` row restored | `ports_renders_the_same_rows_refreshing_and_complete_with_one_status_row`, `refreshing_ports_pane_shows_no_progress` |
| 11: Security `🔗 Status: failed` restored | `failed_tls_scan_renders_one_status_row` |
| 12: `Scanned:` dropped only while refreshing (old behavior) | `ports_renders_the_same_rows_refreshing_and_complete_with_one_status_row` |
| 13: `no reply` back to `timeouts` | `tui_and_no_tui_report_the_same_silent_hop_count` (assertion inverted from `2 timeouts` to `2 no reply`) |

### Open questions
- `--no-tui` reads `, 2 no reply`; Scott may prefer `, 2 hops no reply`.

## Phase 4: Observatory analyzers and grader (pure, no network)

`src/scan/observatory.rs` plus one file per upstream module under `src/scan/observatory/`. Every
file carries the MPL-2.0 Exhibit A header naming `mdn/mdn-http-observatory` at `2776308` and the
upstream file(s) it derives from; the 19 `test/files` pages are copied to
`tests/fixtures/observatory/files/` with the same header as an HTML comment. `LICENSE-MPL-2.0` (the
upstream `LICENSE`, byte for byte) is at the repo root, and `README.md` names the MPL-2.0 tree.

Ported tests: upstream has 103 `it(` in the 15 listed files (csp 16, csp-parser 5, cookies 13, cors
4, redirection 8, referrer-policy 7, strict-transport-security 7, subresource-integrity 10,
x-content-type-options 3, x-frame-options 6, cross-origin-resource-policy 6,
cross-origin-embedder-policy 4, cross-origin-opener-policy 4, grader 5, analyzer-utils 5). The port
has 103 tests in `mod upstream` blocks: `cargo test --lib observatory -- --list | grep -c
'::upstream::.*: test'` prints 103. An `it(` inside a JS loop (csp "header invalid", COOP/COEP
"rejects"/"accepts") is one Rust test looping the same values, so the runtime count upstream (127,
`node --test` over the 15 files) is higher than its literal count.

google.com: `tests/fixtures/observatory/google-com.json` (API scan 132240279) fed through `analyze`
grades `C-` 45, all 12 results and modifiers equal to the API's, `pass` equal to the CLI's, 6
passed (`google_com_grades_c_minus_45_with_the_apis_12_results`). The meta tags come from parsing
the captured body with the port's parser, and they equal the capture's
(`google_com_meta_tags_match_the_capture`).

### Design decisions
- `Retrieval` (the analyzers' only input) is data, in `retriever.rs`: `host`, `http`/`https:
  Option<Session>` (`Session { url, response, redirects }`), `cors: Option<Response>`, `cookies`
  (the `auto` jar), `meta: MetaTags`, `auto_body`. `auto()` is https when present, else http,
  which is upstream's `clientInstanceRecordingRedirects` choice. Phase 5 fills it; nothing in Phase
  4 touches the network.
- `analyze(retrieval, preload, domains) -> Result<ObservatoryResult, AnalyzeError>` in
  `observatory.rs` is `analyzeScan`: status gate (`SiteIsDown`, `UnexpectedStatusCode`), the 12
  tests in `ALL_TESTS` order, `grade::grade`. It returns the doc's `ObservatoryResult` (host,
  algorithm_version 6, score, grade, tests, verified, preload_available) so Phase 5's `observe`
  only retrieves and calls it.
- `TestResult.score_modifier` is filled from the score table when the test runs, and `grade::grade`
  sums the field: that is what lets the 89/90 boundary test feed a synthetic -11.
- `charts.rs` holds upstream's full `SCORE_TABLE` (modifier, description, recommendation for all 77
  results), `GRADE_CHART`, `TEST_TITLES`, `TEST_TOPIC_LINKS`, generated from `charts.js` by a node
  script (not committed); the grader tests read the descriptions and recommendations.
- Headers: `Headers` keeps axios's shape, one entry per case-insensitive name holding
  `HeaderValue::Single` or `HeaderValue::List`, because upstream's results depend on the
  difference (COOP/COEP grade a list of two as invalid; a CSP-Report-Only `[]` is truthy, `""` is
  not). The Node duplicate-join that produces it is Phase 5's.
- HTML: `html.rs` is a port of htmlparser2 12.0.0's tokenizer state machine plus the tree-builder
  state that changes which tags it sees (the open-element stack, foreign-content contexts,
  raw-text elements, implied closes, the second `<form>`, SVG name adjustments, first duplicate
  attribute wins). Text, comments and declarations are tracked as states only. Character
  references are decoded in attribute values only, with entities 8.1.0's attribute-mode rules;
  `html/entities.rs` is the WHATWG named-reference table (2231 entries, generated from Python's
  `html.entities.html5`). `script_discovery_matches_htmlparser2` pins 22 inputs (raw text,
  comments, CDATA, foreign content, plaintext, entities, duplicates) against node's output for
  the same strings.
- Structured fields: `structured.rs` is a full port of structured-headers 2.1.1's `parseItem`
  (every bare-item type, parameters, the trailing-input check), not only the token subset: a
  parameter's value type decides whether the whole header parses (`report-to=coop endpoint` is
  invalid, `report-to` alone is valid). 18 inputs pinned against node.
- CSP: `csp/parser.rs` sorts sources with an ICU `en` collation (punctuation, digits, letters, case
  second), because `parseCsp`'s "drop the longer of two adjacent sources" depends on which sources
  are adjacent. `SourceList` keeps upstream's aliasing: when `script-src` falls back to
  `default-src`, removing `'unsafe-inline'` for a nonce removes it from `default-src` too, as the
  shared `Set` does.
- Cookies: `Cookie::parse` mirrors tough-cookie's `Cookie.parse` (strict mode, last attribute
  wins, `SameSite` only strict/lax/none, `Path` reset by an invalid value). The jar's accept/reject
  rules (domain match, public suffix, prefixes, replacement) are the retriever's, Phase 5; the
  ported cookie tests store parsed cookies as a `Domain=mozilla.org` cookie from
  `https://mozilla.org/` is stored.
- SRI's `tldts` registrable domain is a port trait, `RegistrableDomain`, implemented for any
  `publicsuffix::Psl` (scan's `IcannList`): ICANN only, `None` for an IP or a bare suffix. The
  analyzers stay pure; Phase 5 passes the list `psl.rs` already caches.
- `HstsPreload { entries, available }` with `lookup` (trim, lowercase, exact `force-https`, else the
  first parent with `force-https` and `include_subdomains`, a non-qualifying parent not stopping
  the walk). `HstsPreload::unavailable()` misses every lookup and sets `preload_available=false`;
  `unavailable_preload_scores_as_not_preloaded` pins that the score equals a list lacking the host.
  Parsing Chromium's JSON and the 24h refresh are Phase 5.
- Upstream throws, failing the whole scan, on a redirect hop whose host is not a valid site
  (`Site.fromSiteString`) and on a full-URL `<script src>` that `new URL` rejects. The port returns
  `AnalyzeError::InvalidSite` / `InvalidScriptSrc`: no grade, as upstream gives none.
- `js.rs` holds the JS string semantics the analyzers depend on: `trim` with JS's whitespace set,
  `slice` in UTF-16 units (upstream truncates headers at 1024/256 units), `split(/\s+/)`,
  `Number.parseInt` (so `max-age=forever` is `NaN`, which upstream grades at least six months).

### Deviations
- CORS: production behavior wins (Phase 0c). The port never reads a request `Origin`, so
  `cross-origin-resource-sharing-implemented-with-universal-access` is never emitted. Upstream's
  "checks for universal access" (expects universal, failing) is inverted by name as
  `checks_for_universal_access_grades_restricted_as_production_does` (restricted, passing).
- Files beyond the doc's list, each following its "one file per upstream module" rule: `types.rs`
  (`src/types.js`), `charts.rs` (`src/grader/charts.js`), `csp/parser.rs` (`cspParser.js`),
  `cookies/cookie.rs` (tough-cookie's parser), `structured.rs` (structured-headers), `html/
  entities.rs` (the reference table), `js.rs`, and `helpers.rs` (`test/helpers.js`, test-only).
  `session.rs` is not created: it is network code (Phase 5). `xcto.rs`, `xfo.rs`, `corp.rs`,
  `coop.rs`, `coep.rs`, `referrer.rs` use the doc's short names.
- `grade(tests)` returns `(i32, GradeLetter)`, not the doc's `(i32, Option<GradeLetter>)`:
  `getGradeForScore` maps every score to a grade (floored at 0, keyed at `min(score - score % 5,
  100)`), so a `None` would never occur. "No grade" lives in `AnalyzeError`.
- The ported tests run against an empty preload list plus the specific upstream entries a test
  reads (cloudflare.com, bugzilla.mozilla.org, facebook.com, each copied from the Chromium list of
  2026-10-30), not the 14 MB list itself.
- The copied HTML fixtures are renamed with hyphens (`test_content_sri_no_scripts.html` ->
  `test-content-sri-no-scripts.html`), per the repo's no-underscore rule; each header names the
  upstream file.
- `Cookie.expires` keeps the raw attribute instead of tough-cookie's parsed date: no analyzer and
  no jar rule reads it (Phase 0c: expired cookies are kept and graded). A cookie with an
  unparseable `Expires` therefore shows it in `CookieData` where upstream shows none; results are
  unaffected.
- The HTML parser decodes no entities in text content, and does not port htmlparser2's text,
  comment or processing-instruction callbacks: they never produce an open tag, and a character
  reference never consumes a `<`.
- `tests/fixtures/observatory/google-com.json` stays without an MPL header (JSON has no comments,
  Phase 0 decision): it is captured site data and Observatory's output, not Observatory source.

### Tradeoffs
- One Rust test per upstream `it(` (loops inside) vs one per runtime case: keeps the count checkable
  against `grep -c 'it('` while every upstream value still runs.
- Full structured-field and entity tables vs the subset the doc named: the subset would grade
  `same-origin; a=1.2345` valid (upstream: invalid) and decode `&notin;` wrongly; the tables are
  data, and fidelity is the requirement.
- Porting `SCORE_TABLE`'s descriptions and recommendations (HTML) vs only the modifiers: two
  ported grader tests read them, and Phase 6's zoom can show what a result means.
- An approximate ICU collation (an ASCII order table, non-ASCII after ASCII by code point) vs
  linking ICU: CSP sources are lowercase ASCII in practice; a non-ASCII source would only change
  which of two adjacent sources is dropped.

### Bite proofs
Each fix undone in turn (scripted string mutation of the working tree, `cargo test --lib
observatory`, restore), with the tests it broke:

| Fix undone | Failing tests |
|---|---|
| bonus threshold 90 -> 89 | `grade::bonuses_count_only_from_a_penalty_only_score_of_90` |
| bonuses always count | `grade::bonuses_count_only_from_a_penalty_only_score_of_90`, `google_com_grades_c_minus_45_with_the_apis_12_results` |
| score not floored at 0 | `grade::upstream::gets_the_grade`, `grade::every_score_maps_to_its_bucket`, `grade::heavy_penalties_floor_at_zero` |
| CSP multi-policy intersection (`keep = true`) removed | `csp::parser::upstream::should_parse_policy_correctly`, `csp::upstream::multiple_csp_headers_combined_per_rfc_9110_are_not_treated_as_invalid`, `csp::upstream::multiple_csp_headers_with_differing_policies_produce_correct_intersection` |
| nonce/hash no longer neutralizes `'unsafe-inline'` | `csp::upstream::no_unsafe`, `csp::upstream::unsafe_inline_in_style_src_only` |
| meta-disallowed directives kept | `csp::upstream::ignore_frame_anchestors_in_http_equiv` |
| CSP-Report-Only ignored | `csp::upstream::report_only`, `google_com_grades_c_minus_45_with_the_apis_12_results` |
| `<script>` content not raw text | `html::script_discovery_matches_htmlparser2` |
| attribute entities not decoded | `html::script_discovery_matches_htmlparser2` |
| duplicate attribute: last wins | `html::script_discovery_matches_htmlparser2`, `html::duplicate_attributes_keep_the_first` |
| structured item: trailing input allowed | `coep::upstream::rejects_invalid_headers`, `coop::upstream::rejects_invalid_headers`, `coep::a_joined_duplicate_header_is_invalid`, `coop::a_joined_duplicate_header_is_invalid`, `structured::token_items_match_structured_headers` |
| HSTS comma not invalid | `hsts::upstream::header_invalid` |
| preload parent walk ignores `include_subdomains` | `hsts::preload_lookup_walks_parents_with_include_subdomains` |
| redirection: initial http hop allowed | `redirection::upstream::checks_for_first_redirection_to_http`, `google_com_grades_c_minus_45_with_the_apis_12_results` |
| SRI: `//host` treated as same origin | `sri::upstream::checks_if_implemented_with_external_scripts_and_no_protocol`, `sri::upstream::checks_for_same_origin`, `sri::upstream::checks_if_not_implemented_with_external_scripts_and_no_protocol` |
| cookies ignore HSTS | `cookies::upstream::checks_regular_cookie_no_secure_but_hsts`, `cookies::upstream::checks_session_cookie_no_secure_but_hsts`, `google_com_grades_c_minus_45_with_the_apis_12_results` |
| referrer: first valid policy wins | `referrer::upstream::checks_for_multiple_valid_referrer_headers`, `referrer::upstream::checks_for_private_referrer_header` |
| XFO ignores CSP `frame-ancestors` | `xfo::upstream::checks_implemented_via_csp` |
| CORS universal access restored (echoed origin + credentials) | `cors::upstream::checks_for_universal_access_grades_restricted_as_production_does` |
| status gate rejects 401 | `tests::status_gate_admits_2xx_3xx_401_403` |
| unknown `SameSite` kept as `none` | `cookies::cookie::samesite_keeps_only_strict_lax_and_none` |
| collation is byte order | `csp::parser::collation_matches_icu_en` |

### Open questions
- Third-party notices: `html.rs`, `structured.rs`, `cookies/cookie.rs` and `html/entities.rs` mirror
  htmlparser2 (MIT), structured-headers (MIT), tough-cookie (BSD-3-Clause), entities
  (BSD-2-Clause) and the WHATWG table (CC BY 4.0); each header names the package, version,
  license and copyright holder. They are behavioral ports, not copies. Should the repo also carry
  the full MIT/BSD license texts (e.g. a `THIRD-PARTY-NOTICES` file)?
- `README.md` gained a License section (the repo's README was two lines); Scott may want different
  wording.

## Phase 5: Retriever and HSTS preload

`src/scan/observatory/session.rs` (session.js), `session/transport.rs` (the HTTP layer under it),
`cookies/jar.rs` (tough-cookie's store rules), the retriever in `retriever.rs` (retriever.js),
`observe` in `observatory.rs`, the Chromium list and `PreloadSource` in `hsts.rs`, `Refreshing<T>`
in `src/scan/cache.rs`, and `FakeHttp`/`TestCa` in `src/scan/testing.rs`. Every derived file
carries the MPL-2.0 header. Nothing is wired into `HttpScanner` or the TUI (Phase 6).

Read end to end before writing: `retriever.js`, `session.js`, `url.js`, `utils.js`,
`scanner/index.js`, `retrieve-hsts.js`, `analyzer/hsts.js`, and from `node_modules` tough-cookie
5.1.2 (`cookieJar.js`, `memstore.js`, `permuteDomain.js`, `getPublicSuffix.js`, `domainMatch.js`,
`canonicalDomain.js`, `defaultPath.js`, `pathMatch.js`, `parseDate.js`), http-cookie-agent 8.0.0's
cookie glue and axios 1.20.0's http adapter (decompression, `stripBOM`).

Live check (temporary `#[ignore]` test, not committed; Phase 6 owns the live test), 2026-10-30,
from talos: `observe` with `Retriever::standard()`, the cached public suffix list and Chromium's list
fetched the same hour (10614168 bytes, sha256 `d132107c...2486c`, parses in 27 ms): google.com C- 45,
github.com A+ 115, www.tatari.tv B 75, example.com F 10, mozilla.org B+ 80, all 12 results and
modifiers equal to Phase 0b's API table for each host.

Success criteria (all tests, `cargo test --lib`, 758 passing):

| Criterion | Test(s) | Result |
|---|---|---|
| Eight redirection results via FakeHttp | `retriever::tests::network::redirection_{to_https,all_redirects_preloaded,not_needed_no_http,off_host_from_http,not_to_https_on_initial_redirection,not_to_https,missing}`, `untrusted_certificate_grades_unverified_and_the_jar_survives_the_retry` (invalid-cert) | pass |
| Two STS headers -> `hsts-header-invalid` | `two_sts_headers_grade_hsts_header_invalid` | pass |
| Untrusted cert -> `verified=false`, jar survives the retry | `untrusted_certificate_grades_unverified_and_the_jar_survives_the_retry` | pass |
| robots.txt cookie only on the fallback path | `robots_cookie_reaches_the_jar_only_on_the_fallback_path` | pass |
| 500 -> unexpected status | `a_500_is_an_unexpected_status` (`Err(AnalyzeError::UnexpectedStatusCode(500))`) | pass, data level |
| Five preload fixtures | `preload_fixtures_grade_through_the_chromium_list` (Chromium-format JSON through `parse_chromium`, full retrieval per host) | pass |
| No cache + dead URL: same result and score as a list lacking the host, `preload_available=false` | `an_unavailable_list_scores_as_a_list_lacking_the_host`, `no_cache_and_a_dead_url_is_the_unavailable_list` | pass, data level; the `· preload list unavailable` grade-line text is Phase 6 display |
| Stalled https session hits its 10s cap, scan returns within 35s, paused time | `retriever::tests::budget::a_stalled_https_session_hits_its_cap_and_the_scan_still_returns` (returns graded at exactly 28 s), `session::tests::slow_hops_end_at_the_session_cap` (10 s) | pass; the target observation half is Phase 6 |

### Design decisions
- A transport port, `session::Transport` (`send(OutgoingRequest) -> IncomingResponse`), with `ReqwestTransport` as the production implementation: `session.rs:run`, `session/transport.rs`. Redirects, cookies, the certificate retry and both timeouts live in the session logic, as they do in session.js on top of Node's agents. The same logic runs over loopback sockets in the FakeHttp tests and over a scripted transport in the paused-time tests.
- `ReqwestTransport` builds two clients from `TransportOptions` (`built_in_roots`, `extra_roots` DER, `resolve`, `env_proxy`): `Policy::none`, `http1_only`, no pool reuse, one verifying and one with `danger_accept_invalid_certs` (`rejectUnauthorized` true/false). That builder is where a test CA is injected. `env_proxy` defaults on because axios honors `HTTP_PROXY`/`HTTPS_PROXY`; tests turn it off.
- Request shape exactly as Phase 0b recorded: session hops send Observatory's UA, `Accept`, `Accept-Encoding: gzip, compress, deflate, br`, `Connection: close` and the jar's `Cookie`; robots.txt and the preflight send `Connection: keep-alive` and their own `Accept`/`Origin`/`Access-Control-Request-Method`: `session.rs:follow`, `SessionRun::auxiliary`. reqwest's `brotli` and `deflate` features were enabled (`cargo add`) so bodies decode as axios's do; reqwest decodes on the response's `Content-Encoding` whatever request header was set.
- Certificate errors are any rustls `InvalidCertificate` in the error chain: `transport.rs:certificate_error`. hyper-util wraps an `io::Error` (Other) around tokio-rustls's `io::Error` (InvalidData) around the rustls error, and `io::Error::source()` skips what it wraps, so the walk descends through `get_ref` (found by logging the chain when the first version missed it).
- The retry (`session.rs:init`) clears the history, keeps the jar and the redirect count, flips to the non-verifying client, and stays under the original 10 s session deadline (the axios `signal` is copied into the retry's instance). The auxiliary client then switches too (`Aux::Fallback`): non-verifying, the jar on https requests only (the fallback client sets `httpsAgent` alone), its own 10 s deadline from the retry, and a 2xx answer pushed onto the session's history by the interceptor the retry attaches. So on the fallback path robots.txt joins `httpsRedirects` and the preflight goes to robots.txt (`redirectHistory.at(-1)`); `robots_cookie_reaches_the_jar_only_on_the_fallback_path` pins both.
- Auxiliary requests follow redirects the follow-redirects way (any 3xx with a `Location`, at most 10, a 303 turns OPTIONS into GET) and keep axios's default `validateStatus`: a non-2xx final answer is `None`, which is how a 405 preflight becomes `cors = null` (Phase 0b).
- A missing `Location` resolves as `undefined` (`new URL(undefined, base)`), an unusable one fails the session, and after 10 followed redirects the 11th redirect answer is the session's response: `session.rs:follow`.
- Response headers are joined the Node way (`session.rs:node_headers`): `set-cookie` always a list, Node's 18 first-wins names keep the first value, `cookie` joins with `"; "`, everything else with `", "`. Header values are latin1 both ways (`transport.rs:latin1_decode`/`latin1_encode`), as Node reads and writes them. Bodies are lossy UTF-8 with a leading BOM stripped (`decode_body`).
- `CookieJar` (`cookies/jar.rs`) mirrors tough-cookie as http-cookie-agent drives it (`setCookieSync(.., { ignoreError: true })`, `getCookiesSync` for the header): public-suffix rejection with RFC 6761 special-use names allowed, `domainMatch`, `hostOnly`, `defaultPath`, `__Secure-`/`__Host-` prefixes, replacement in place by (domain, path, key), expired cookies stored. Read from the source and not in Phase 0c: `getCookies` removes an expired cookie from the store when a later request's lookup matches it, so an expired cookie set on a redirect hop is gone from the jar if a later hop's request matches it. The port does the same (`cookie_header`), with `parseDate` ported for the expiry check.
- tough-cookie's `getPublicSuffix` calls tldts `getDomain` with the private section on; the SRI test's tldts call is ICANN only. `observe` takes `SuffixLists { icann, all }` and the retriever passes `all` to the jars: `observatory.rs:observe`.
- `is_html` copies `headers["content-type"]?.split(";", 1)[0]` against `HTML_TYPES` with no trim or lowercasing: `retriever.rs:is_html`.
- `Retriever::with_ports` mirrors upstream's `httpPort`/`httpsPort` options; the tests use it to reach fakes on ephemeral ports, with every test name resolved to 127.0.0.1 through `TransportOptions::resolve`.
- `parse_chromium` (`hsts.rs`) is `retrieveAndStoreHsts`'s parse: `//` to end of line stripped everywhere (inside strings too, which breaks such a file as upstream's regex does), names trimmed and lowercased, a later duplicate winning, `mode == "force-https"`, `!!include_subdomains`. The cached file is Chromium's raw JSON; the parsed list is held in memory.
- `PreloadSource` (`hsts.rs`) owns the copy for its lifetime through `cache.rs:Refreshing<T>`: the first `get` loads through `CachedSource::load_aged` (cache if fresh, else fetch, else a stale cache); after that the in-memory copy is served until it reaches 24 h, then each `get` attempts `CachedSource::refresh` (fetch only, no disk re-read) and keeps the copy on failure. With no copy at all, `get` returns `HstsPreload::unavailable()`, so a missing list is never an empty one.
- `FakeHttp` gained `FakeRoute` (method, `Host`, path, status, repeated headers, bytes body, `stall`), a request log with headers (`FakeRequest`), `start_tls` with a `TestCa`-issued `ServerIdentity` (openssl-built CA and SAN leaf, tokio-rustls acceptor), and `port()`. It now stops when dropped instead of after 5 s without a request, so a slow test never loses its server; every existing caller keeps the server bound for the test's life.

### Deviations
- `observe(retriever, host, preload, lists) -> Result<ObservatoryResult, AnalyzeError>` instead of the doc's `observe(host, pin, preload) -> ObservatoryResult`. Same effect, correct seam: `pin` was dropped by the 2026-10-30 no-per-family decision; there is no result for a site that is down or answers an unexpected status (`analyze` already returns `Result`, Phase 4); the retriever carries the client builder the doc asks the test CA to go through; the jar needs the suffix lists.
- Timeouts: axios's `timeout` (9 s) is Node's socket idle timeout, the port's is 9 s total per request, which is what the doc's budget says. They differ only for a server that keeps trickling bytes past 9 s; the 10 s session cap bounds both.
- The stall criterion runs over a scripted transport, not FakeHttp: with paused time tokio advances the clock whenever the runtime is idle, including while a socket read is pending, so a loopback fake would race the clock. FakeHttp covers the socket paths with the clock running. The 35 s inner budget and the "target observation" half belong to `HttpScanner` (Phase 6); this phase shows the Observatory part returns at 28 s, the doc's worst case.
- "500 gives `Failed(unexpected status)`" and "the grade line shows `preload list unavailable`" are asserted at the data level (`AnalyzeError::UnexpectedStatusCode(500)`, `preload_available == false`); `ObservatoryOutcome` and the grade line are Phase 6.
- Bodies: reqwest decodes `gzip`, `deflate` and `br` only. axios also decodes `x-gzip`, `compress`, `x-compress` and (where Node has it) `zstd`; such a body stays encoded here. axios's `forcedJSONParsing` turns a JSON-parseable body into an object, the port keeps the text; it matters only for a JSON-parseable body served as `text/html`.
- reqwest's decoder drops `Content-Length` from a decoded response, where axios keeps it, and reorders names after removing `Content-Encoding`. No analyzer reads either.
- Enabling reqwest's `brotli`/`deflate` also changes the existing `HttpScanner` client's automatic `Accept-Encoding` (now `gzip, br, deflate`). Its request is replaced in Phase 6.
- The `Cookie` header orders by path length then creation, one value per key; tough-cookie's own order also depends on its store's object-key order. Only what servers receive can differ; nothing is graded on it.
- `canonicalDomain`'s IPv6 handling is approximated by an `Ipv6Addr` parse (brackets stripped).

### Tradeoffs
- A transport trait vs reqwest's `cookie_store` and redirect policy: reqwest cannot express the retry's "same jar, cleared history, new client" or the aux client's jar-on-https-only, and the trait makes the budget testable in paused time.
- Generic `Refreshing<T>` in `cache.rs` vs a preload-only holder: the rule (parse once per refresh, keep the copy on failure) is about the cache, not HSTS, and the suffix list re-parse Phase 0 flagged could use it.
- Bite proofs ran as scripted string mutations of the working tree with `cargo test --lib`, then restored. Every undo below broke at least one test:

| Fix undone | Failing tests |
|---|---|
| certificate walk without `get_ref` descent | `transport::invalid_certificate_inside_an_io_error_is_a_certificate_error`, `robots_cookie_reaches_the_jar_only_on_the_fallback_path`, `untrusted_certificate_grades_unverified_and_the_jar_survives_the_retry` |
| retry resets the jar | `untrusted_certificate_grades_unverified_and_the_jar_survives_the_retry` |
| retry keeps the history | `untrusted_certificate_grades_unverified_and_the_jar_survives_the_retry` |
| normal-path aux client uses the jar | `robots_cookie_reaches_the_jar_only_on_the_fallback_path` |
| aux answers recorded on the normal path | `auxiliary_follows_redirects_and_rejects_non_2xx`, `robots_cookie_reaches_the_jar_only_on_the_fallback_path` |
| preflight to the start URL, not the history's last hop | `robots_cookie_reaches_the_jar_only_on_the_fallback_path` |
| duplicate headers: last wins | `duplicate_headers_join_the_node_way`, `two_sts_headers_grade_hsts_header_invalid` |
| no 10 s session cap | `slow_hops_end_at_the_session_cap`, `a_stalled_https_session_hits_its_cap_and_the_scan_still_returns` |
| no 9 s request timeout | `a_silent_request_ends_at_the_request_timeout` |
| missing `Location` ends the chain | `a_redirect_without_location_goes_to_undefined` |
| redirect limit off by one | `ten_redirects_are_followed_and_the_eleventh_is_the_response` |
| redirects never followed | 11 tests, incl. `redirection_to_https`, `redirection_off_host_from_http`, `redirection_not_to_https_on_initial_redirection`, `redirection_not_to_https` |
| non-2xx aux answer kept | `auxiliary_follows_redirects_and_rejects_non_2xx`, `a_non_2xx_preflight_is_no_cors_response`, `robots_cookie_reaches_the_jar_only_on_the_fallback_path` |
| brotli decoding off | `a_brotli_body_is_decoded_and_its_meta_tags_read` |
| preload names not trimmed/lowercased | `chromium_list_parses_with_comments_names_trimmed_and_lowercased`, `duplicates_take_the_last_entry_and_flags_follow_js_truthiness`, `preload_fixtures_grade_through_the_chromium_list` |
| `mode` ignored | `chromium_list_parses_with_comments_names_trimmed_and_lowercased`, `preload_fixtures_grade_through_the_chromium_list` |
| no comment stripping | `a_double_slash_inside_a_string_breaks_the_parse_as_upstream`, `chromium_list_parses_with_comments_names_trimmed_and_lowercased`, `preload_fixtures_grade_through_the_chromium_list`, `the_list_is_fetched_cached_and_parsed_once` |
| no list -> empty list | `no_cache_and_a_dead_url_is_the_unavailable_list`, `an_unavailable_list_scores_as_a_list_lacking_the_host` |
| failed refresh drops the copy | `refreshing_retries_a_stale_copy_and_keeps_it_on_failure` |
| stale copy never refreshed | `refreshing_retries_a_stale_copy_and_keeps_it_on_failure` |
| expired matches kept on lookup | `cookie_header_matches_and_drops_expired_matches` |
| cross-domain cookie accepted | `cross_domain_cookies_are_rejected_and_parent_domains_kept` |
| HTML type check lowercases | `html_type_is_the_exact_mime_before_the_first_semicolon` |
| BOM kept | `body_is_lossy_utf8_without_a_bom` |

### Open questions
- Phase 6 must hand the jar an ICANN-plus-private suffix list (`publicsuffix::List`); `psl.rs` parses the ICANN section only (`IcannList`). Both can come from the one cached file.
- The expired-cookie removal on a later matching request is ported from tough-cookie's source; Phase 0c's crafted server only measured cookies set on the last hop. A cross-hop check against the local CLI would confirm it.

## Phase 6: Wire the Observatory grade into scan

`HttpScanner` now runs three independent parts: the target observation (per family, as before), the
host's Observatory run (`ObservatoryOutcome`, in `observatory.rs`), and, in Phase 7, the lenses.
`assemble` in `scan/http.rs` joins them. The old penalty grade is deleted; `tui/http.rs`,
`tui/security.rs` and `pretty.rs` read the outcome. The ignored live test is
`scan::observatory::live::scan_matches_the_live_observatory_api` (`observatory/live.rs`).

Live test run (`cargo test --release --lib -- --ignored --exact --nocapture
scan::observatory::live::scan_matches_the_live_observatory_api`), 2026-10-30, from talos, sandbox
on (the API was reachable). Result: `test result: ok. 1 passed`, 383.64 s. Output:

```
google.com (pair 1/4): google.com
    API: scan id 132262723, scanned_at 2026-10-30T09:48:12.964Z, C- (45)
    scan: C- (45), verified=true, preload_available=true
    preload sha256: d132107cad8e71df05e39b042a23843ea1eba648f8206f42ab59e070e2d2486c
google.com: identical
www.tatari.tv (pair 1/4): www.tatari.tv
    API: scan id 132263074, scanned_at 2026-10-30T09:50:05.251Z, B (75)
    scan: B (75), verified=true, preload_available=true
    preload sha256: d132107cad8e71df05e39b042a23843ea1eba648f8206f42ab59e070e2d2486c
www.tatari.tv: identical
github.com (pair 1/4): github.com
    API: scan id 132263079, scanned_at 2026-10-30T09:50:06.633Z, A+ (115)
    scan: A+ (115), verified=true, preload_available=true
    preload sha256: d132107cad8e71df05e39b042a23843ea1eba648f8206f42ab59e070e2d2486c
github.com: identical
example.com (pair 1/4): example.com
    API: scan id 132263049, scanned_at 2026-10-30T09:49:58.514Z, F (10)
    scan: F (10), verified=true, preload_available=true
    preload sha256: d132107cad8e71df05e39b042a23843ea1eba648f8206f42ab59e070e2d2486c
example.com: identical
mozilla.org (pair 1/4): mozilla.org
    API: scan id 132263258, scanned_at 2026-10-30T09:50:56.304Z, B+ (80)
    scan: B+ (80), verified=true, preload_available=true
    preload sha256: d132107cad8e71df05e39b042a23843ea1eba648f8206f42ab59e070e2d2486c
mozilla.org: identical
neverssl.com (pair 1/4): neverssl.com
    API: scan id 132263282, scanned_at 2026-10-30T09:51:02.509Z, D (30)
    scan: none (site down)
    preload sha256: d132107cad8e71df05e39b042a23843ea1eba648f8206f42ab59e070e2d2486c
neverssl.com: retrying the pair after the API's cooldown
neverssl.com (pair 2/4): neverssl.com
    API: scan id 132263607, scanned_at 2026-10-30T09:52:40.917Z, D (30)
    scan: F (10), verified=true, preload_available=true
    preload sha256: d132107cad8e71df05e39b042a23843ea1eba648f8206f42ab59e070e2d2486c
neverssl.com: retrying the pair after the API's cooldown
neverssl.com (pair 3/4): neverssl.com
    API: "The site seems to be down."
    scan: none (site down)
    preload sha256: d132107cad8e71df05e39b042a23843ea1eba648f8206f42ab59e070e2d2486c
neverssl.com: identical
test scan::observatory::live::scan_matches_the_live_observatory_api ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 775 filtered out; finished in 383.64s
```

Five hosts agreed on the first pair. neverssl.com flapped as Phase 0 measured: pair 1 had the API at D 30 while scan saw the site down, pair 2 had the API at D 30 and scan at F 10 (only one port answered each side), and pair 3 had both sides report the site down, which the test counts as agreement.

Success criteria (all tests, `cargo test --lib`, 775 passing plus the one ignored live test):

| Criterion | Test(s) | Result |
|---|---|---|
| HTTP pane for google fixture: `Grade: C- (45) · google.com` in `WARN`; zoom lists all 12 tests | `tui::http::tests::google_fixture_shows_the_grade_score_and_host_in_warn_and_zoom_lists_12_tests` | pass |
| Security pane shows the same grade | `tui::security::tests::http_grade_csp_and_cors_show_observatory_results` | pass |
| `pretty.rs` shows the same grade | `pretty::tests::http_grade_matches_the_panes_text_for_every_outcome`, `http_prints_https_failure_and_the_hosts_grade` | pass |
| IP -> `Grade: n/a (IP address)`, `localhost` -> `Grade: n/a (not a public hostname)`, both `MUTED` | `tui::http::tests::hosts_with_no_grade_read_why_in_muted`; `observatory::tests::eligible_host_refuses_ips_and_dotless_names`; `http::tests::observatory_host_is_the_urls_host_never_its_port_or_path`; end to end `an_ip_target_is_not_graded_and_sends_no_observatory_request` | pass |
| Site down -> `Grade: none (site down)` | same `hosts_with_no_grade...` test; `http::tests::a_working_url_with_a_down_site_returns_ok_with_both` | pass |
| URL fails, grade works: both shown, scan `Ok` | `tui::http::tests::a_failed_url_and_a_working_grade_show_together`, `http::tests::a_failed_url_with_a_working_grade_returns_ok_with_both`, `assemble_returns_ok_when_the_url_fails_and_the_host_grades`, `pretty::tests::http_prints_a_failed_url_and_a_working_grade_together` | pass |
| Both failing -> `Err` | `http::tests::a_failed_url_and_a_down_site_return_err`, `assemble_returns_err_only_when_the_url_and_the_grade_both_fail` | pass |
| `· preload list unavailable` in `WARN` on the grade line | `tui::http::tests::a_missing_preload_list_is_noted_in_warn_on_the_grade_line`; end to end `http::tests::a_missing_preload_list_grades_and_says_so` | pass |
| `HttpScanner::deadline()` 40s, inner 35s budget returns partial results | `http::tests::the_scan_deadline_leaves_the_inner_budget_room_to_return_partial_results`, `a_stalled_grade_returns_the_target_observation_at_the_budget`, `a_stalled_observatory_run_ends_at_the_session_cap_inside_the_budget` (paused time) | pass |
| Live test | `scan::observatory::live::scan_matches_the_live_observatory_api` | see below |

### Design decisions
- Outcome on `HttpResult`, not `HttpData`: `observatory: ObservatoryOutcome` lives on `HttpResult` beside the per-family results (`scan/http.rs:HttpResult`). It is one value per scan whatever `p` selects, and the doc's "URL fails, grade works" case has no `HttpData` to carry it.
- Scan `Ok` iff the target observation succeeded for some family or the host graded (`http.rs:assemble`). A host Observatory refuses (`NotApplicable`) is not a grade: a failing IP target is still `Err` with the URL's own reason (the typed `NoAddress` survives), as it was before. When both fail and the grade `Failed`, the error reads `IPv4: operation timed out; grade: site down`.
- `HttpStatus::Success` carries nothing, `HttpResult::new(observatory)` takes the outcome (no `Default`, no "not run" value), `HttpData` lost `security_grade`, `CspPolicy` lost `strength`, `CorsPolicy` lost `security_level`.
- The target observation and the two families run concurrently (`tokio::join!`), each under the 35s budget through `timeout_at`; a family cut off reads `operation timed out` through the route classifier. `HttpScanner.budget` is a field (default 35s) so a test can shrink it.
- The Observatory part cannot reach 35s on its own: sessions end at 9s/10s, robots.txt and the preflight add 9s each, 28s worst case (Phase 5). The budget is the backstop for a slow suffix-list or preload fetch (10s each, concurrent with each other, ahead of `observe`); it yields `Failed("timed out")`.
- One public suffix file, two lists: `psl::parse_suffixes` returns `Suffixes { icann: IcannList, all: List }` from the one cached file under the same ICANN-marker corruption check, held in memory by a `Refreshing<Suffixes>` on `HttpScanner` (parsed once per 24h refresh, not per scan). This resolves Phase 5's open question. The jars get `all`, the SRI test `icann`.
- A missing suffix list fails the grade loudly (`Failed("public suffix list unavailable: ...")`) instead of grading with a wrong jar. A missing preload list does not: it grades as "not preloaded" with `preload_available=false` (the doc's rule).
- `ObservatoryOutcome::from_analysis` maps every `AnalyzeError` (site down, unexpected status, invalid site, invalid script src) to `Failed(error.to_string())`; the Display strings (`site down`, `HTTP 500`) are the grade line's wording. `grade_summary`/`grade_text`/`preload_unavailable` live on the outcome so the HTTP pane, Security pane and `pretty.rs` share one wording; the panes own only color (`tui/http.rs:grade_line`, letter -> GOOD / WARN / BAD, `NotApplicable` and `Failed` -> MUTED).
- `eligible_host` (`observatory.rs`) ports `validHostname`'s trailing-dot strip, IP refusal and dotless refusal. The API's TLD-list check is not ported: a name under an unknown TLD is retrieved and reads as site down.
- The plain-HTTP fallback for a bare host stays as target observation (it shows the URL's real status when HTTPS fails and keeps `https_failure` in the pane); only the forced `F` is deleted. The grade is the host's Observatory run, independent of it.
- Security pane: `CSP:` and `CORS:` rows show Observatory's result string for `content-security-policy` and `cross-origin-resource-sharing`, colored by the test's `pass`; the target's own policy text and `CspIssue`/`CorsIssue` lists stay as listed facts. The `HTTP Grade:` row is the shared grade line. When the URL failed but the host graded, the HTTP section is the grade line alone.
- Zoom lists the 12 tests as `name: result (+N)` under `Observatory tests (algorithm 6)`, colored by `pass`.
- Live test (decision for Scott to confirm, also an open question): each host is retried as a pair (fresh `POST /scan` plus `analyze`, then a fresh local grade) up to 4 times, 61s apart (the API returns the earlier scan for a repeat POST inside 60s; measured 2026-10-30, the second POST of example.com returned the same scan id), until the two sides agree. Both sides reporting site down (`422 scan-failed` vs `Failed("site down")`) is agreement. neverssl.com stays in the list, per the doc. A POST or analyze that returns 5xx or errors is retried 3 times 15s apart; the HTTP timeout is 120s (google.com takes 15-60s). A disagreement prints the provenance: API scan id, `scanned_at`, grade and score, our `verified` and `preload_available`, the sha256 of the cached Chromium list, our effective URL (from a second retrieval) and every difference by name. The comparison covers each test's result string and modifier, score, grade and `algorithm_version` 6, never `pass`.

### Deviations
- `ObservatoryOutcome` is in `observatory.rs` and held by `HttpResult`, not `HttpData` (see Design decisions): same effect, correct seam.
- `Failed(reason)` carries no host, so the no-grade line reads `Grade: none (site down)` as the Architecture bullet says, not `Grade: none (site down) · example.com` as the result-model example in the doc does. The criteria text (`Grade: none (site down)`) holds either way. Adding the host needs a `String` on `Failed`/`NotApplicable`; say if you want it.
- `HttpVulnerability` lost `WeakCsp` and `InsecureCors` as well as `InformationDisclosure`: they were derived from the deleted `CspStrength` and `CorsSecurityLevel`, which the Resolved Decisions delete ("Two signals never encode one fact"). `assess_vulnerabilities` lost its `cors` argument. The four `Missing ...` header-presence issues stay.
- `test_http_scanner_timeout` is deleted: it asserted nothing (both arms empty) and, with the new scan, would have made live requests to httpbin.org and written `~/.cache/scan`. The scanner timeout paths are covered by the loopback tests above.
- Tests that pinned the old grade were deleted, not inverted, because the behavior no longer exists: `test_security_grade_calculation`, `test_security_grade_edge_cases`, `test_csp_strength_calculation`, `test_cors_security_levels`, `missing_hsts_lowers_score_exactly_once`, `information_disclosure_is_still_penalized`, `security_grade_labels`, `test_vulnerability_assessment` (http.rs), `render_grade_comes_from_primary_result_not_best_family` and the A+ label test (`tui/http.rs`). `render_plain_http_fallback...` and `https_failure_falls_back...` were inverted: the fallback no longer forces `F`, and each asserts that.
- `Observatory run resolves once per scan, whatever p selects`: on a target with no address in the selected family the scan used to be `Err(NoAddress)`; it is now `Ok` when the host grades, with the target block replaced by `no address to request`. The doc's rule (Err only when both fail) produces this.

### Tradeoffs
- `Refreshing<Suffixes>` on `HttpScanner` vs reusing `SuffixList::registrable_domain` per call: the latter re-parses the 338 KB list per scan (the Phase 0 finding for DNS); the held copy costs one `Arc` and reuses Phase 5's `Refreshing`.
- Failing the grade on a missing suffix list vs bundling a list: the doc has no bundled data and the jar rules need the PRIVATE section; failing visibly (`none (public suffix list unavailable: ...)`) beats a quietly different grade. The list is cached on disk after the first fetch and a stale copy of any age is kept.
- Injecting `Retriever`, `PreloadSource` and `SuffixList` through `HttpScanner::with_observatory` vs a trait for the whole Observatory run: the three concrete types are already the seams Phase 5 built (transport port, `from_url`, `SuffixList` fields), so the end-to-end tests run the real code over loopback.
- Bite proofs ran as scripted string mutations of the working tree with `cargo test --lib`, then restored. Every undo broke at least one test:

| Fix undone | Failing tests |
|---|---|
| `assemble` errs on a URL failure even when the host graded | `a_failed_url_with_a_working_grade_returns_ok_with_both`, `assemble_returns_ok_when_the_url_fails_and_the_host_grades` |
| `assemble` never errs | `a_failed_url_and_a_down_site_return_err`, `assemble_returns_err_only_when_the_url_and_the_grade_both_fail`, `a_stalled_observatory_run_ends_at_the_session_cap_inside_the_budget`, `timed_out_scan_renders_operation_timed_out_in_the_pane` |
| `deadline()` left at the runner default | `the_scan_deadline_leaves_the_inner_budget_room_to_return_partial_results` |
| IP addresses graded | `observatory::tests::eligible_host_refuses_ips_and_dotless_names` |
| C grades colored `BAD` | `every_grade_letter_is_colored_by_its_letter`, `google_fixture_shows_the_grade_score_and_host_in_warn_and_zoom_lists_12_tests`, `tui::security::tests::http_grade_csp_and_cors_show_observatory_results` |
| preload note dropped from the grade text | `pretty::tests::http_grade_matches_the_panes_text_for_every_outcome`, `a_missing_preload_list_grades_and_says_so`, `observatory::tests::grade_text_names_the_grade_score_and_host` |
| zoom lists no tests | `google_fixture_shows_the_grade_score_and_host_in_warn_and_zoom_lists_12_tests` |
| host dropped from the grade text | 14 tests across `pretty`, `http`, `tui::http`, `tui::security`, `observatory` |
| Security pane drops the grade line | `http_grade_csp_and_cors_show_observatory_results`, `security_pane_grade_line_for_hosts_with_no_grade_and_a_failed_url` |
| `pretty.rs` drops the grade | `http_grade_matches_the_panes_text_for_every_outcome`, `http_prints_a_failed_url_and_a_working_grade_together`, `http_prints_https_failure_and_the_hosts_grade` |
| PRIVATE section ignored in the jar's list | `psl::tests::suffixes_read_the_one_file_with_and_without_the_private_section` |
| no inner budget on the grade | `a_stalled_grade_returns_the_target_observation_at_the_budget` |

### Open questions
- neverssl.com in the live test: kept, with a 4-pair retry and "both site down is agreement" (Scott's call on this was open since Phase 0). It adds up to 3 minutes of cooldown waits when the host flaps. Keep this rule, or replace the host by a dated Resolved Decision?
- The HTTP pane's `Issues:` list (`Missing HSTS` and three more) comes from the target observation's own request, which still sends `scan/1.0` over reqwest. google.com sends HSTS only to Observatory's Firefox UA over HTTP/1.1, so the pane can show `Missing HSTS` beside a grade whose HSTS test passed. The doc says the target observation stays "as today". Should those four issues go, or the target observation adopt Observatory's request shape?
- No-grade lines carry no host (see Deviations). Add it?
- The API's TLD-list check is not ported (`eligible_host`); a dotted name under an unknown TLD reads `none (site down)`, not `n/a`. Acceptable, or port `conf/tld-list.json`?

## Phase 7: Lenses

`LensOutcome<T>` in `src/scan/lens.rs`, shared by HTTP and DNS. The timing probe and the ALPN
handshake in `src/scan/http/timing.rs` (`Prober`), security.txt in `src/scan/http/disclosure.rs`,
the redirect, cookie and `alt-svc` views of the Observatory retrieval in `src/scan/http/views.rs`.
`HttpScanner` runs the lenses beside the target observation and the grade (`probe_lenses`,
`grade_and_view` in `scan/http.rs`) and keeps them on `HttpResult::lenses`. MTA-STS and TLS-RPT are
read in `scan/dns.rs` (`lookup_mail_transport`, `tagged_value`) onto `EmailSecurityAnalysis`, and
`txt_at` returns the query status. The HTTP zoom (`tui/http.rs:lens_lines`) and the Security zoom
(under `DMARC:`) render them.

Live check, 2026-10-30, from talos, release build in `tui-test` at 200x55 (not the installed
binary; AC6 proper is the parent's, after release):

- `github.com`, `shift+tab` x5, `Enter`: `🧬 ALPN: h2`, `⏱ DNS: 0ms · Connect: 36ms · TLS: 12ms · TTFB: 66ms · Transfer: 178ms`, `alt-svc: none`, `security.txt: present · https://hackerone.com/github`, `http:// route: http://github.com/ 301 → https://github.com/ 200`, `Cookies: 3 cookies` (`_gh_sess`, `_octo`, `logged_in` with their flags).
- `google.com`, `Enter` (Security): `MTA-STS: 20210803T010101`, `TLS-RPT: mailto:sts-reports@google.com`, rows under `DMARC: configured`. `dig +short TXT` gave `"v=STSv1; id=20210803T010101;"` and `"v=TLSRPTv1;rua=mailto:sts-reports@google.com"`.

Success criteria (all tests, `cargo test --lib`, 815 passing plus the one ignored live test):

| Criterion | Test(s) | Result |
|---|---|---|
| Local TLS fake: valid HTTP/1.1 exchange, ALPN `http/1.1`, each phase non-zero, sum within 5ms of wall time | `http::timing::tests::the_timed_request_is_a_valid_http1_exchange_whose_phases_sum_to_the_wall_time` (asserts the fake negotiated `http/1.1`, the request line, `Host`, `Connection: close`, every phase non-zero, phases <= wall and wall - phases < 5ms) | pass |
| ALPN handshake reports `h2` when offered and sends no request bytes | `the_alpn_handshake_reports_h2_and_sends_no_request`; `a_server_without_alpn_negotiates_none` | pass |
| Plain-HTTP fake reads `TLS: n/a` | `a_plain_http_url_has_no_tls_phase` (`tls == None`); `tui::http::tests::timing_reads_each_phase_and_n_a_for_the_phases_a_url_skips`; end to end `http::tests::lenses_probe_the_target_and_read_the_retrievals_route_and_jar` (zoom contains `TLS: n/a`) | pass |
| A fake that stalls after the handshake gives `Failed` for timing; the scan still returns | `http::tests::a_target_that_stalls_after_the_handshake_fails_timing_and_the_scan_returns` (timing `Failed("timed out")`, scan `Ok` and graded in < 5s); `timing::tests::a_server_that_stalls_after_the_handshake_never_completes_the_probe` | pass |
| security.txt `present`, `expired`, `invalid`, `absent` (404 and soft-404 HTML), `failed` (timeout) | `http::disclosure::tests::fetched_files_classify_over_tls` (all four served over TLS by a fake), `a_text_file_with_a_contact_and_a_future_expiry_is_present`, `a_past_expiry_is_expired`, `no_contact_or_a_bad_expiry_or_a_wrong_type_is_invalid`, `a_404_and_a_soft_404_html_page_are_absent`, `a_silent_server_fails_with_a_timeout`, `an_untrusted_certificate_fails` | pass |
| A DNS fixture renders `MTA-STS:` and `TLS-RPT:` values | `dns::tests::mta_sts_and_tls_rpt_are_read_at_the_host_from_a_dns_fixture` (a UDP DNS fake on loopback); `tui::security::tests::zoom_shows_mta_sts_and_tls_rpt_under_dmarc` | pass |
| A resolver error renders `failed`, not `none` | `dns::tests::a_dns_failure_reads_failed_never_none` (a silent resolver: `txt_at` is `Err(Timeout)`, both lenses `Failed("timed out")`); `tui::security::tests::a_failed_mail_transport_query_reads_failed_not_none` (`MTA-STS: failed: timed out` in `BAD`, `TLS-RPT: none` in `MUTED`) | pass |
| Redirect and cookie views show the `http` route and the `auto` jar's flags | `http::views::tests::views_show_the_http_route_the_auto_jar_and_alt_svc`; end to end `lenses_probe_the_target_and_read_the_retrievals_route_and_jar` (a 301 to `/home` setting `pref=1; HttpOnly; SameSite=Lax` reads `http:// route: http://site.com:<p>/ 301 → http://site.com:<p>/home 200` and `pref: no Secure · HttpOnly · SameSite=lax`); `tui::http::tests::cookie_rows_list_each_flag_and_color_by_whether_all_are_set` | pass |

### Design decisions
- Lenses on `HttpResult`, not `HttpData`: `HttpResult::lenses: Lenses` (`scan/http.rs`), beside `observatory`, as Phase 6 placed the grade. They are one reading per scan whatever `p` selects, and they must be reachable when the URL failed: the HTTP pane shows them in zoom on the no-target-observation branch too (`tui/http.rs`, "The lenses do not need the URL to have answered"). `HttpResult::new(observatory, lenses)` takes them; no default, no "not run" value outside `#[cfg(test)] Lenses::absent()`.
- `Lenses { timing, alpn, security_txt, retrieval: Option<RetrievalViews> }`. `RetrievalViews { alt_svc, http_route, cookies }` is computed from the `Retrieval` inside `grade_and_view` and the retrieval (with its body) is dropped there. `retrieval` is `None` only when no retrieval ran: a host Observatory refuses, a missing suffix list, or a grade cut off by the 35s budget. Those three rows then read `n/a (<reason>)` or `failed: <reason>` from the grade outcome (`tui/http.rs:no_retrieval`).
- `observatory::observe_retrieval` returns the analysis and the retrieval; `observe` keeps its signature and calls it, so `live.rs` and the Phase 5 tests are untouched. `grade_host` keeps returning `ObservatoryOutcome` for the live test.
- Each lens runs under its own 9s timeout (`HttpScanner::lens`, `LENS_TIMEOUT`); the three probing lenses run concurrently (`probe_lenses`), the set runs concurrently with the target observation and the grade, and the set is also cut off at the 35s budget. A lens that runs out reads `failed: timed out`. A lens never changes `assemble`'s `Ok`/`Err`.
- `Prober` (`timing.rs`) holds three seams: `HostLookup` (hickory with the system configuration in production, a function in tests), `TcpConnector` (`src/scan/connect.rs`) and the root store. The timing request and the ALPN handshake both verify the certificate against the same webpki root store the TLS scanner uses; there is no bypass client in the lenses.
- The timed exchange is hand-written HTTP/1.1 over the raw (TLS) stream: reqwest exposes no phase times. Phases are cut back to back (`started → looked up → connected → handshaken`, then `written → first byte → end`); the only time not in a phase is the request write. The body is counted, not kept; `Body` decodes chunked framing incrementally (size line, data, CRLF, trailers), `Content-Length` ends at its length, a close-delimited body at EOF, 204/304/1xx have none, interim 1xx heads are skipped. A body cut short is an error, not a short transfer. A TLS peer closing without `close_notify` reads as EOF.
- Timing goes to `request_plan(target).primary` (the URL as given; a bare host is `https://host/`) at `target.primary_ip_for_protocol(protocol)`. ALPN goes to the URL's host on port 443 (`LensProbes::https_port`) at the same address, offering `h2, http/1.1`, then sends `close_notify` and nothing else.
- security.txt (`disclosure.rs`): reqwest with built-in roots (verifying), `scan/1.0`, up to 10 redirects, resolved normally (not pinned), `https://<host>:443/.well-known/security.txt`. Classified by `classify(status, content_type, body, now)`: 404 and 410 `Absent`; any other non-2xx `Failed("HTTP <n>")`; 2xx `text/html` `Absent` (soft 404); 2xx with any type but `text/plain` `Invalid("served as <type>")`; `text/plain` with no `Contact:` `Invalid("no Contact:")`, an `Expires:` that is not RFC 3339 `Invalid("unparseable Expires: ...")`, a past one `Expired`, else `Present`. Field names match case-insensitively; `#` comments are skipped.
- `alt-svc`: every `alt-svc` value of the `auto` response, joined `", "`; the row appends `(HTTP/3)` when an entry is `h3` or `h3-<draft>` (`views.rs:advertises_h3`). The `http://` route is the `http` session's recorded hops (`redirects`, which include the final hop); `Absent` when port 80 gave no response. Cookies are the `auto` jar (`Retrieval::cookies`), name plus Secure, HttpOnly and SameSite; a cookie with all three is `GOOD`, else `WARN`. No auto response makes all three `Failed("site down")`.
- MTA-STS and TLS-RPT (`dns.rs:lookup_mail_transport`): `_mta-sts.<host>` and `_smtp._tls.<host>` asked concurrently, alongside DMARC, the host only (trailing dot dropped). `tagged_value` takes the first record whose first tag is `v=STSv1` / `v=TLSRPTv1` and returns its `id` / `rua`; no such record or an empty value is `Absent`; a failed query is `Failed(<resolver error>)` and a timeout `Failed("timed out")`.
- `txt_at` returns `Result<Vec<String>, QueryStatus>`. DMARC keeps its configured/missing reading: `lookup_dmarc` folds a failed query into "no record" as before (`unwrap_or_default`, commented at the call).
- Display (`tui/http.rs:lens_lines`, `lens_value`): each row is the value, `none` (`MUTED`) or `failed: <reason>` (`BAD`). The timing row is `⏱ DNS: 3ms · Connect: 12ms · TLS: 20ms · TTFB: 45ms · Transfer: 2ms` in whole milliseconds, so `TTFB: \d+ms` matches; an IP host reads `DNS: n/a`, a plain URL `TLS: n/a`; a failed probe reads `⏱ Timing: failed: <reason>`. security.txt reads `present · <contact>`, `expired · Expires: <date>`, `invalid (<why>)`, `absent` or `failed: <reason>`. Security zoom puts `MTA-STS:` then `TLS-RPT:` directly under `DMARC:`. All lens rows are zoom only.
- Tests never leave loopback: the Phase 6 scanner tests now run with `offline_lenses` (instant lookup, `site.com` resolved to 127.0.0.1, an unlistened HTTPS port, only the test CA trusted), and `timed_out_scan_renders_operation_timed_out_in_the_pane` too. `testing.rs` gained `tls_acceptor(identity, alpn)` and `FakeHttp::start_tls_alpn`; the DNS lens tests run a UDP DNS fake on loopback built from hickory's `Message`.

### Deviations
- `LensOutcome` lenses live on `HttpResult::lenses`, not `HttpData` (Data Model). Same effect, correct seam: `HttpData` is per family and absent when the URL fails; the lenses are per scan and must survive a failed URL (the Phase 6 seam).
- `alt_svc` is not a top-level lens field; it sits with the redirect and cookie views in `RetrievalViews`, all three read off one retrieval, and the group is `Option` (`None` = no retrieval ran) instead of three separate `Failed` values. The rows still read `n/a`/`failed` per lens.
- `probe(host, ip, port) -> (HttpTiming, Option<String>)` became `Prober::probe(&self, url: &Url, ip) -> eyre::Result<HttpTiming>` plus `Prober::alpn(host, ip, port) -> eyre::Result<Option<String>>`. Same effect, correct seam: the timed request needs scheme and path (the doc's own "target URL as given"), the ALPN protocol comes from the separate handshake, and the network seams live on `Prober` so the tests inject a lookup and a root store.
- `HttpTiming.dns` is `Option<Duration>` (an IP host has no lookup) and `HttpTiming` carries the response `status`. The doc typed `dns` as `Duration`.
- security.txt states beyond the doc's list: 410 is `absent` like 404; any other non-2xx is `failed: HTTP <n>`; a 2xx that is neither `text/plain` nor `text/html` is `invalid (served as <type>)`. The `absent` state renders `absent`, as the security.txt bullet names it, not the generic `none`.
- `SecurityTxtState::Invalid` carries its reason, shown as `invalid (<why>)`.

### Tradeoffs
- A hand-written HTTP/1.1 exchange vs hyper or reqwest for the timed request: reqwest exposes no connect/TLS/first-byte instants, and hyper's would need a custom connector to see them; the raw stream gives exact boundaries with no new crate.
- Verifying certificates for timing and ALPN vs a bypass verifier: a self-signed or expired target reads `failed: TLS handshake: ...` for both rather than a measurement over an untrusted chain; the TLS pane already reports the certificate. Fail closed, and no `danger` verifier to audit (open question below).
- A fresh hickory resolver per probe vs one held resolver: no hickory cache between scans, so the DNS phase measures the system stub's answer; on a host with a caching stub it reads `0ms` for a warm name (github.com did). Holding a resolver would read `0ms` more often.
- A UDP DNS fake in the tests vs a resolver trait: the fake exercises `txt_at`, `timed_lookup` and the record parsing as they run, with no new production seam.
- Bite proofs ran as scripted string mutations of the working tree with `cargo test --lib <filter>`, then restored. Every undo broke at least one test:

| Fix undone | Failing tests |
|---|---|
| `txt_at` folds a failed query into an empty answer | `dns::tests::a_dns_failure_reads_failed_never_none` |
| the timed request offers `h2` too | `timing::tests::the_timed_request_is_a_valid_http1_exchange_whose_phases_sum_to_the_wall_time` |
| the ALPN handshake writes a request | `timing::tests::the_alpn_handshake_reports_h2_and_sends_no_request` |
| a plain `http://` URL gets a TLS phase | `timing::tests::a_plain_http_url_has_no_tls_phase`, `http::tests::lenses_probe_the_target_and_read_the_retrievals_route_and_jar` |
| transfer measured from the request write | `timing::tests::the_timed_request_is_a_valid_http1_exchange_whose_phases_sum_to_the_wall_time` |
| no per-lens timeout | `http::tests::a_target_that_stalls_after_the_handshake_fails_timing_and_the_scan_returns` |
| a soft-404 HTML page not absent | `disclosure::tests::a_404_and_a_soft_404_html_page_are_absent`, `fetched_files_classify_over_tls` |
| a past `Expires:` not expired | `disclosure::tests::a_past_expiry_is_expired`, `fetched_files_classify_over_tls` |
| the route read from the `https` session | `views::tests::views_show_the_http_route_the_auto_jar_and_alt_svc`, `views::tests::nothing_on_port_80_no_cookies_and_no_header_are_absent`, `http::tests::lenses_probe_the_target_and_read_the_retrievals_route_and_jar` |
| Security zoom drops the MTA-STS/TLS-RPT rows | `tui::security::tests::zoom_shows_mta_sts_and_tls_rpt_under_dmarc`, `a_failed_mail_transport_query_reads_failed_not_none` |
| lenses hidden when the URL failed | `tui::http::tests::lenses_show_when_the_url_failed_and_views_read_n_a_for_a_refused_host` |

### Open questions
- Timing and ALPN verify the certificate, so a self-signed or expired target (`selfsigned-200`, `expired-200` in the shakedown) reads `failed: TLS handshake: invalid peer certificate: ...` for both. Keep, or measure over an unverified handshake as Observatory's fallback does?
- A security.txt with a `Contact:` and no `Expires:` reads `present`, as the doc's states define it; RFC 9116 §2.5.5 makes `Expires` required. Should a missing `Expires:` be `invalid`?
- The ALPN handshake always goes to port 443, as the doc says, even for `https://host:8443/`. Should it follow the target's port when the target is HTTPS?
- DMARC still reads `missing` when its query fails (only MTA-STS and TLS-RPT got the `failed` state). Give DMARC the same?
- MTA-STS: with two `v=STSv1` records RFC 8461 §3.1 says no policy is available; `tagged_value` reads the first. Flag that case as `invalid`?
- `--no-tui` (`pretty.rs`) prints none of the lenses; the doc places them in the two zooms only. Add them there?

## Implementation audit fixes

Audit synthesis: `/home/saidler/.cache/review-panel/runs/1LhRTHSc/synthesis.md` (probes in `probes.md` beside it). Fixes items 1-6 of the synthesis, and question 4 (the live test's both-down rule).

| Item | Fix | Test(s) |
|---|---|---|
| 1. Two signals for one fact | Deleted `HttpVulnerability`, `assess_vulnerabilities`, `HttpData::vulnerabilities`, `total_vulnerabilities`, `get_all_vulnerabilities`, the HTTP pane `Issues:` list, the Security pane `❗ HTTP Vulnerabilities` block, and `pretty.rs`'s `N vulnerabilities`. Deleted `CspIssue`/`CorsIssue`, the `issues` fields and `analyze_csp_issues`/`analyze_cors_issues` along with their bullets. Security pane HSTS, X-Frame, X-Content, Referrer and CSP rows go through `tui/security.rs:observatory_row`: Observatory's test result when graded, else the target's header value (or `missing`) in `MUTED` | `tui::security::tests::header_rows_show_only_observatorys_verdict_when_the_target_request_saw_none` (google.com grade, `scan/1.0` saw no headers: `HSTS: hsts-implemented-max-age-at-least-six-months` GOOD, no `HSTS: no`/`Missing`/`Vulnerabilities`, zoom too); `header_rows_with_no_grade_show_the_targets_headers_muted`; `tui::http::tests::redirects_that_fit_take_one_row_and_no_header_issue_list_is_shown` (inverted from `..._and_every_issue_name_stays_visible`); `pretty::tests::http_prints_the_grade_and_no_count_of_the_targets_missing_headers` |
| 2. `plural()` everywhere | `plural` is generic over any integer (`From<u8>`). Routed: Security `MX:`, `Certificate Chain:`, cert `Expires: N days`; WHOIS zoom `Age:`; HTTP `Size: N bytes`; `pretty.rs` `A records`, `security features`, traceroute `hops` | `tui::security::tests::zoomed_content_lists_the_certificate_chain_and_dmarc_in_full` (inverted from `1 certificates`, plus `MX: 1 record`), `expiry_of_one_day_reads_day`, `tui::whois::tests::domain_age_of_one_day_reads_in_the_singular`, `tui::http::tests::a_one_byte_body_reads_byte`, `pretty::tests::counts_of_one_are_singular`, `tui::text::tests::plural_adds_an_s_unless_the_count_is_one` |
| 3. security.txt gated on the family's address | `probe_lenses`: only timing and ALPN need `ip`; security.txt runs on the URL's host regardless | `scan::http::tests::security_txt_runs_when_the_selected_family_has_no_address` |
| 4. RDAP contact with empty `fn` and a phone dropped | `parse_contact_info` keeps a contact when any of name, organization, email, phone, address is present | `scan::whois::tests::empty_fn_with_only_a_visible_phone_keeps_the_contact`, `a_vcard_of_only_empty_values_is_no_contact` |
| 5. Cookie `Expires` raw, last-wins | `Cookie::parse` runs `jar::parse_date` on the attribute and assigns only a date that parses. `Cookie.expires`/`CookieData.expires` are `Option<SystemTime>`; `jar::expiry_time` reads it directly. tough-cookie 5.1.2 `dist/cookie/cookie.js`, `case 'expires'`: `const exp = parseDate(av_value); // "If the attribute-value failed to parse as a cookie date, ignore the cookie-av." if (exp) { c.expires = exp; }` | `cookies::cookie::tests::an_unparseable_expires_is_ignored_and_keeps_the_earlier_date`, `cookies::jar::tests::a_past_expires_followed_by_garbage_is_expired_at_lookup` (`Expires=<1970>; Expires=garbage` is dropped at lookup) |
| 6. No-grade line omits the host | `ObservatoryOutcome::Failed { host, reason }`; `grade_summary` reads `none (<reason>) · <host>` in the HTTP pane, Security pane and `--no-tui`. `n/a (<reason>)` stays hostless | `observatory::tests::grade_text_names_the_grade_score_and_host`, `tui::http::tests::hosts_with_no_grade_read_why_in_muted`, `a_working_url_and_a_failed_grade_show_together`, `tui::security::tests::security_pane_grade_line_for_hosts_with_no_grade_and_a_failed_url`, `pretty::tests::http_grade_matches_the_panes_text_for_every_outcome`, `scan::http::tests::a_working_url_with_a_down_site_returns_ok_with_both` |
| 7. Live test both-down counted as agreement | `live.rs:pair_verdict` -> `Agree` only for a graded pair with no differences (12 test results and modifiers, score, grade, algorithm_version); `BothDown` is a retry; 4 pairs with no `Agree` fails with the last pair's provenance | `observatory::live::tests::site_down_on_both_sides_is_a_retry_and_one_sided_is_a_difference`, `identical_graded_results_agree` |

Bite proofs (scripted mutation of the working tree, `cargo test --lib <filter>`, restored after):

| Fix undone | Failing tests |
|---|---|
| Security rows read the target's headers, not Observatory | `header_rows_show_only_observatorys_verdict_when_the_target_request_saw_none`, `http_grade_csp_and_cors_show_observatory_results` |
| `pretty.rs` prints a count of the target's missing headers | `pretty::tests::http_prints_the_grade_and_no_count_of_the_targets_missing_headers` |
| Security `MX: {} records` / `{} certificates` | `zoomed_content_lists_the_certificate_chain_and_dmarc_in_full` (each) |
| Security `{} days` | `expiry_of_one_day_reads_day` |
| `pretty.rs` `{} A records` / `{} security features` / `{} hops` | `pretty::tests::counts_of_one_are_singular` (each) |
| WHOIS `{age} days` | `domain_age_of_one_day_reads_in_the_singular` |
| HTTP `{} bytes` | `a_one_byte_body_reads_byte` |
| security.txt gated on `ip` | `security_txt_runs_when_the_selected_family_has_no_address` |
| RDAP keep condition without phone | `empty_fn_with_only_a_visible_phone_keeps_the_contact` |
| Unparseable `Expires` overwrites | `an_unparseable_expires_is_ignored_and_keeps_the_earlier_date`, `a_past_expires_followed_by_garbage_is_expired_at_lookup` |
| No-grade line without host | `grade_text_names_the_grade_score_and_host`, `hosts_with_no_grade_read_why_in_muted`, `a_working_url_and_a_failed_grade_show_together`, `security_pane_grade_line_for_hosts_with_no_grade_and_a_failed_url`, `http_grade_matches_the_panes_text_for_every_outcome`, `a_working_url_with_a_down_site_returns_ok_with_both`, `assemble_returns_ok_when_the_url_works_and_the_grade_fails` |
| Both-down counts as agreement | `site_down_on_both_sides_is_a_retry_and_one_sided_is_a_difference` |

The HTTP pane's `Issues:` removal has no mutation proof: the list read a field that no longer exists, so the compiler is the guard. Its test is the inverted redirect test above, which asserts no `Issues:` or `Missing` row next to a google.com grade.

Live test, 2026-10-30 10:43-10:51Z, from talos, `cargo test --release --lib -- --ignored --exact --nocapture scan::observatory::live::scan_matches_the_live_observatory_api`: **FAILED** on neverssl.com. Every other host matched on pair 1:

```text
google.com (pair 1/4): API scan id 132274887, scanned_at 2026-10-30T10:43:40.100Z, C- (45); scan: C- (45), verified=true, preload_available=true -> identical
www.tatari.tv (pair 1/4): API scan id 132275339, scanned_at 2026-10-30T10:45:33.447Z, B (75); scan: B (75) -> identical
github.com (pair 1/4): API scan id 132275344, scanned_at 2026-10-30T10:45:35.097Z, A+ (115); scan: A+ (115) -> identical
example.com (pair 1/4): API scan id 132275226, scanned_at 2026-10-30T10:45:03.919Z, F (10); scan: F (10) -> identical
mozilla.org (pair 1/4): API scan id 132275435, scanned_at 2026-10-30T10:45:58.074Z, B+ (80); scan: B+ (80) -> identical
neverssl.com (pair 1/4): API "The site seems to be down."; scan: D (30)
neverssl.com (pair 2/4): API "The site seems to be down."; scan: F (10)
neverssl.com (pair 3/4): API scan id 132276236, scanned_at 2026-10-30T10:49:22.164Z, D (30); scan: none (site down) · neverssl.com
neverssl.com (pair 4/4): API "The site seems to be down."; scan: none (site down) · neverssl.com -> both down, nothing compared
preload sha256 (all pairs): d132107cad8e71df05e39b042a23843ea1eba648f8206f42ab59e070e2d2486c
panicked: scan disagrees with the live Observatory API: neverssl.com ... effective URL: no session answered
    differences: both sides report the site down: no graded pair to compare
test result: FAILED. 0 passed; 1 failed; finished in 482.15s
```

neverssl.com stays in `HOSTS`. In 4 pairs the two sides were never up at the same time, so nothing could be compared. Pair 2 is new: scan graded F (10) where pair 1 graded D (30), against an API that was down. That is the host flapping between ports 80 and 443 mid-retrieval, and this run cannot tell it apart from a grading difference. After the run, the failure report's pair label moved from the end of the provenance (after the preload hash) to its front, `pair N/4: <provenance>`. That is a format change only, and the test was not re-run for it.

### Design decisions
- Security pane header rows: `observatory_row` (`tui/security.rs`) is the one place a header row gets a verdict. With no grade (IP target, site down, timed out) the row shows what the target sent, in `MUTED`, never colored as a pass or fail. CSP joins it, so a missing CSP with no grade is now `missing` in `MUTED` (it was `BAD`).
- `CspIssue`/`CorsIssue` deleted along with their bullets, not just hidden. `unsafe-inline`, wildcard origins and the rest are what Observatory's CSP and CORS tests judge, so keeping the parsed lists would keep the second signal in the data model. `CspPolicy.directives` and the CORS fields stay for display (Security pane, HTTP zoom).
- `ObservatoryOutcome::Failed` is a struct variant carrying the graded host (`failed(host, reason)` builds it; `from_analysis(host, ..)`). The host is the one Observatory was asked about, not the target's display name, so a URL target names its host without the port or path. Every no-grade cause carries it, including `timed out` and `public suffix list unavailable`.
- `plural` is generic (`N: Display + PartialEq + From<u8>`), so `u8` hop counts and `i64` day counts use the same helper as `usize` lengths. A negative count reads plural (`-3 days`).
- Cookie expiry is parsed once, at the attribute, into `Option<SystemTime>`. That mirrors tough-cookie, which stores a `Date`, and leaves no path where an unparseable string reaches the jar. `CookieData.expires` carries the same type. The google.com fixture's `serializeSync` ISO dates are parsed in `observatory::tests::jar_cookie`.
- Live test: `PairVerdict { Agree, BothDown, Differ }` from `pair_verdict`. `differences` now reports any side without a grade as a difference, and both-down is classified before it.

### Deviations
- The CSP row's no-grade fallback changed from `missing` in `BAD` to `missing` in `MUTED` (not named in the audit). A red `missing` is a verdict from the target request, the class item 1 removes.
- `probe_lenses` now reports a failed request plan with its own error, not `no address to connect to`.
- The Phase 4 note (Deviations: "`Cookie.expires` keeps the raw attribute ... results are unaffected") is superseded here. `Cookie.expires` is now parsed and an unparseable value is ignored, as upstream does.

### Tradeoffs
- Struct variant `Failed { host, reason }` vs passing the host at render time: the three surfaces (HTTP pane, Security pane, `--no-tui`) would each have to derive the Observatory host from the target the same way `observatory_host` does. Carrying it on the outcome keeps one source.
- Deleting the CSP/CORS issue analysis vs keeping it for the zoom: the zoom already shows the raw policy and header values, and Observatory's result names the problem. A second list would only disagree with it.

### Open questions
- The live test now fails on neverssl.com whenever the two sides are never up together in 4 pairs, as it did in this run. The doc's only relief is a dated Resolved Decision with your say-so: swap the host for a stable plain-HTTP host, or keep it and accept a red run when it flaps?
- `--no-tui` still prints `N security features`: a count of the security headers the `scan/1.0` request saw. It is not a pass or fail, but it is the target request's reading of the same headers Observatory grades (google.com reads `0 security features` beside an HSTS pass). Drop it as well?
- XSS-Protect and Permissions rows still color the target's own header (`GOOD`/`WARN`) since Observatory has no test for them, as instructed. Should they go `MUTED` like the other no-grade rows?

## Pre-release: drop the `--no-tui` security-features count

### Design decisions
- `pretty.rs` HTTP line no longer prints `N security features`; `count_security_features` is deleted. The count read the `scan/1.0` target request's headers, so google.com printed `0 security features` beside a passing Observatory HSTS test: a second signal for the fact the grade already encodes. Scott chose "fix then bump" (2026-10-30).

### Deviations
- None.

### Tradeoffs
- Delete vs. recount from Observatory's passing tests: the grade line already carries that verdict; a recount would be a derived field that duplicates it.

### Open questions
- XSS-Protect and Permissions rows still color the target's own header (no Observatory test for either); `partial (some contact fields visible)` wording. Both left for Scott, not release blockers.

## Post-release: AC3 and AC5 failed on installed v0.5.9

### Design decisions
- AC3 (`src/scan/dns.rs`, `DNS_REQUERY_FLOOR` 10s -> 2s). Installed v0.5.9 on ripr, be.tatari.tv: longest `TTL: expired` run 5. Cause, sampled every 2s: one re-query refreshes every type, timed to the earliest expiry + 1s; at t=47 TXT refreshed while another type's stub entry was in its last second and came back TTL 0; the 10s floor held the next re-query to t=57. Scott chose "A: lower the floor to 2s" (the stub caches by TTL, so upstream load is unchanged). Test `a_type_returned_with_ttl_zero_is_requeried_within_two_seconds` fails with the floor at 10s. After: longest run 1.
- AC5 (`src/main.rs`, `cap_malloc_arenas`, `mallopt(M_ARENA_MAX, 2)` before the runtime starts; `#[tokio::main]` replaced by a hand-built multi-thread runtime; `libc` added). Installed v0.5.9: 660s->900s +1416 KB. Same build, RSS every 60s for 900s: default 40000 -> 54476 KB, `MALLOC_ARENA_MAX=1` 36544 -> 37516 KB (+200 KB 660->900), so the growth is glibc arenas, not retained data. Scott chose "A: cap arenas at startup". After (2s floor + cap): 37176 KB at 60s, 40040 at 660s, 40044 at 900s (+4 KB).

### Deviations
- The DNS floor (doc: "Clamp stays 10s..60s") is now 2s..60s, by Scott's choice after AC3 failed.

### Tradeoffs
- Arena cap vs. cutting allocation churn per source (parse the suffix list once per refresh, measure HTTP's transients): the cap covers whatever allocates next; per-source fixes regress with each new scanner.

### Open questions
- No unit test can observe allocator arenas; the 900s RSS series is the evidence.

## Post-release: the three open questions (Scott: "do all three")

### Design decisions
- XSS-Protect and Permissions rows are `MUTED` whether the header is present or missing: `src/tui/security.rs`. Observatory has no test for either, so a `GOOD`/`WARN` color was a verdict nobody graded, beside rows that carry Observatory's. `1; mode=block` read `GOOD`, against MDN's advice to send `0` or omit the header. Test: `xss_protect_and_permissions_rows_are_muted_present_or_missing`, which fails on the old colors.
- `PrivacyLevel::Partial` keeps `partial (some contact fields visible)`: it matches `open (contacts visible)`, the level then what shows.
- `THIRD-PARTY-NOTICES` at the repo root carries the full license texts of htmlparser2 12.0.0 and structured-headers 2.1.1 (MIT), tough-cookie 5.1.2 (BSD-3-Clause) and entities 8.1.0 (BSD-2-Clause), fetched from each package at that version on unpkg, plus the CC BY 4.0 attribution for the WHATWG entity table. `README.md`'s License section points to it.

### Deviations
- None.

### Tradeoffs
- CC BY 4.0 gets attribution, the license URL and the change note, not the full legal code: that is what the license's section 3(a) asks for.

### Open questions
- The release tarballs carry only the `scan` binary (v0.5.10 linux-amd64: `tar tzf` lists `scan`). The BSD licenses ask a binary redistribution to reproduce the notice "in the documentation and/or other materials". The archive contents come from the shared `tatari-tv/github-actions-public` `rust-cli-release.yml@v2.0.0` workflow, not this repo.
