# Design Document: Pane split, DNS/security reorder, keys and help

**Author:** Scott Idler
**Date:** 2026-11-06
**Status:** Draft
**Review Passes Completed:** 5/5 (see Pass Log)
**Review Panel:** round 1 folded in (see Review Panel Round 1)

## Summary

The dns and security panes overflow on a typical target, so the CA, PTR and email records sit below the fold. The goal is to put as much useful information on the page as possible; past that, scrolling and zoom are the fallback. This plan does it in three ways:

- split the cert and mail content into two new panes, placed where connectivity and the near-empty row-1 panes have room;
- reorder dns and security so the most important rows lead;
- add the review feedback from the scan Slack thread: human TTLs, hjkl, a key legend, a btop-style Esc menu with help, and a fix for the dated globe glyph.

## Problem Statement

### Background

- v0.6.0 shipped the btop look (rounded colored boxes, braille latency graph, black background).
- Posted in Slack (#C01FXF7P3ST, thread 1793999876.032139). keegan and patrick.shelby replied with feedback.
- Measured at 200x56 against google.com with the installed v0.6.0:
  - dns: 39 content rows in a 20-row box, `↓ 19 more`. TXT alone is 18 of them (17 records + header).
  - security: 40 rows, `↓ 20 more`. TLS 20 (cert details 8 of those), HTTP security 12, email security 8.
  - connectivity: 70% of row 0 wide, mostly empty space beside a 2-line graph.
  - ports and geoip: 4 and 6 rows used of 20.
- Re-measured on `target/debug/scan` v0.6.0 with `--wait 20`: dns `↓ 20 more`, security `↓ 20 more`, whois `↓ 2 more`. The counts move a row or two with live DNS answers.

### Problem

- The CA, PTR and email posture sit below the fold. The user has to scroll or zoom to see the rows reviewers called most important.
- No key hints on the main page, and h/l do nothing.
- TTLs read `6908s (cached)`, hard to read at a glance.
- 🌐 U+1F310 is the one emoji that FiraCode Nerd Font Mono carries itself. The terminal draws the font's monochrome outline instead of a color emoji ("lookin' a little 1993").

### Goals

Traceability: S = Scott, K = keegan, P = patrick.shelby.

- G1 (S): at 200x56 on a typical target, the page shows as much useful information as it can, most important rows first. Some overflow is fine; scrolling and zoom are the fallback ("just trying to get as much useful info on the page"). Break out a cert pane and/or another pane, and take room from connectivity.
- G2 (K): PTR at the top with apex/A.
- G3 (K): TXT out of the default view, still in zoom.
- G4 (K, S): TTL as compact human time, `2h50m14s`, keeping the live countdown.
- G5 (K): CA at the top, visible right away; known-distrusted CAs styled differently.
- G6 (K): DNSSEC and SPF/DKIM shown. SPF exists today; DNSSEC is WHOIS-only and zoom-only; DKIM is `not checked`.
- G7 (P, S): h/j/k/l movement.
- G8 (P, S): help. Esc opens a btop-style menu with Help; `?` opens help directly.
- G9 (S): a key legend (arrows, hjkl, `?`), right-justified on the top edge of the upper-left (target) pane.
- G10 (K, S): replace the globe glyph.

### Non-Goals

- Renaming the tool (S: "we wont rename yet"). Parked until Scott raises it.
- Zero overflow in every pane. S: "we can have some overflow".
- DNSSEC chain validation (RRSIG verification against the root). Parked: needs hickory's `dnssec` feature and a trust anchor. Revisit if "DS published" proves insufficient.
- A browser-grade distrust verdict. scan does not verify the chain or read SCTs (see Bad CA).
- A config file for scan. The distrusted-CA list is a static table (see Resolved Decisions).
- Changing any CLI (non-TUI) output except where it shares a formatter.
- Spatial (grid-geometric) pane movement. h/l follow the existing pane-list order, as ←/→ do.

## Proposed Solution

### Overview

1. Two new panes, `cert` and `mail`. Content moves out of security; no scan logic is duplicated.
2. Grid rebalance:
   - Row 0: target 30 | connectivity 40 | cert 30.
   - Row 1: whois | http | ports | geoip | mail, 20% each.
   - Row 2: unchanged.
3. Reorder:
   - dns: PTR first; TXT collapsed to one count row in the grid.
   - cert: CA first after the status row.
4. Keys:
   - h/l = ←/→ (pane), j/k = ↓/↑ (scroll, unchanged).
   - Esc opens the menu in the grid and leaves zoom when zoomed.
   - `?` opens help.
5. A key legend on the target pane's top border, right-justified.
6. One duration formatter for TTLs and SOA timers.
7. Glyph swap plus a lint that bans the offenders.

### Architecture

**Grid** (`src/tui/layout.rs` `grid_layout`):

| row | height | panes (width %) |
|---|---|---|
| 0 | 25% | target 30, connectivity 40, cert 30 |
| 1 | 35% | whois 20, http 20, ports 20, geoip 20, mail 20 |
| 2 | 40% | dns 33, traceroute 33, security 34 |

- Rows 0 and 1 gain one cell each. Heights do not change, so target keeps its 12 inner rows (it needs exactly 12).
- `DEFAULT_GRID_COLS` (`src/tui/layout.rs`) goes from 4 to 5. `pane_rect` returns `None` for `col >= grid_cols`, and render skips that pane, so without this change mail at (1,4) never draws.
- Why row 0 for cert: cert content is about 10 rows (status, CA, validity, subject, key, SAN count, presented chain), which fits row 0's 12 inner rows. Connectivity at 40% of 200 cols is still 78 graph columns, 156 samples.
- Why row 1 for mail: ports and geoip use 4 to 6 of 20 rows. Five columns at 200 cols are 40 wide each. whois's longest grid row, `client transfer prohibited` plus indent, fits.

**The pane list becomes one table.**

- Today it is written twice, in `TuiApp::new` (`src/tui/mod.rs:109-117`) and `create_default_layout` (`src/tui/mod.rs:344-371`).
- Adding two panes in two places is how they drift. Phase 4 makes one `fn panes() -> Vec<(Box<dyn Pane>, PaneConfig)>` that both call.

**Row budgets** (google.com, counted from the v0.6.0 capture, 20 inner rows at 200x56). These are targets, not hard limits: overflow past them falls back to scroll and zoom (G1).

security after the split keeps:

- the handshake rows: status, version, cipher;
- the features: PFS, OCSP;
- the HTTP security headers;
- the grade and issue count.

Only rendering moves. The grade (Observatory, via the `http` scanner) and the issue list (the `tls` scanner) are computed as today.

| step | rows |
|---|---|
| today | 40 |
| cert details move to `cert` | -8 (32) |
| email security moves to `mail` | -8 (24) |
| grade and issues fold into the status row, `Status: analyzed · A+ · 0 issues` | -2 (22) |
| the `Security Features` header drops; PFS and OCSP share one row, `PFS: yes · OCSP: not checked` | -2 (20) |

dns:

| step | rows |
|---|---|
| today | 39 |
| TXT header + 17 values collapse to one `TXT: 17 records (Enter)` row | -17 (22) |
| PTR moves to the top | 0 (22) |

- dns keeps about `↓ 2 more`. The rows that fall below the fold are the last ones, the SOA detail. Accepted per G1.

Zoom keeps the long form of everything.

**cert pane** (`src/tui/cert.rs`):

- Data source: `TlsData.certificate_chain: Vec<CertificateInfo>` (`src/scan/tls.rs`, the `TlsData` struct), from the `tls` scanner. `security.rs:278-342` and `zoomed_tls_lines` (`security.rs:603-669`) render it today. Those blocks move, not copy.
- Grid rows, in order:
  1. `Status: analyzed`, from the `tls` scanner via `crate::tui::status_label`. A failed or refreshing scan shows here, so a kept old result is never shown as current without a label.
  2. `CA: Google Trust Services (WE2)` (G5)
  3. `Valid: yes · 53 days`
  4. `Subject: *.google.com`
  5. `Key: EC 256bit`
  6. `SAN: 65 domains`
  7. `Chain (as sent):` with one row per certificate the server presented.
- Edge cases:
  - No certificate (handshake failed, empty chain): the status row carries the reason and no other rows draw.
  - An issuer with no O= and no CN=: the CA row falls back to the joined `issuer` string.
- The chain is what the server sent, not a verified path. scan connects with `SslVerifyMode::NONE` and reads `peer_cert_chain` (`analyze_certificate_with_openssl`, `src/scan/tls.rs`). The root is usually not sent, so the pane does not claim to show it.
- Zoom adds the full chain detail and the SAN list (both moved from security's zoom).

**Bad CA** (a known-distrusted-CA warning, not a browser verdict):

- `src/scan/tls/distrust.rs` (declared as `mod distrust;` in `tls.rs`, no `mod.rs`) holds a static `&[DistrustedCa { organizations: &[&str], distrusted_after: Option<NaiveDate>, source }]`. `organizations` lists every O= value the distrust covers, because some affected CAs issue under other names (Entrust also under AffirmTrust).
- What it matches, from what scan can see:
  - the `issuer_organization` of each presented certificate. The leaf's issuer is always present, even when the server sends no intermediates;
  - the leaf's `notBefore > distrusted_after` (or no date = always).
- Why it is a heuristic: Chrome's actions key on the root and, for Entrust, the leaf's earliest SCT date. scan verifies no path and parses no SCTs. `notBefore` stands in for the SCT date, since a cert is logged when it is issued. The doc and the label say "distrusted CA", never "browser-rejected".
- A match renders the CA row and the matching chain row in `theme::BAD`, with ` (distrusted CA)`.
- The entries are browser distrust actions: Symantec, WoSign/StartCom, Camerfirma, Entrust, Chunghwa Telecom, NetLock. Each one is verified against the Chrome Root Program / Mozilla bug before it goes in, with its URL in `source`. Dates from memory are not accepted.

**Issuer organization:**

- Today's issuer is one joined string, `C=US, O=Google Trust Services, CN=WE2`, built in `parse_certificate` (`src/scan/tls.rs`) from OpenSSL's `issuer_name().entries()`. Splitting that string on `, ` breaks `O=Entrust, Inc.`.
- Add `issuer_organization: Option<String>` and `issuer_common_name: Option<String>` to `CertificateInfo`. `parse_certificate` reads them with `issuer_name().entries_by_nid(Nid::ORGANIZATIONNAME)` and `Nid::COMMONNAME`. x509-parser is in `Cargo.toml` but unused in `src`; this plan does not use it.

**mail pane** (`src/tui/mail.rs`):

- Data source: `DnsResult.email_security: Option<EmailSecurityAnalysis>` (`src/scan/dns.rs`), the same struct security reads today.
- The first row is `Status:` from the `dns` scanner via `status_label`, like cert.
- An IP target has no `email_security` (the dns scan builds it only for names). mail then shows `not applicable (IP target)` under the status row.
- Shows what security's email block shows today: SPF, DMARC, MTA-STS, TLS-RPT.
- Zone: DNSSEC and DKIM are looked up at the registrable domain of `Target.domain`. `Target.domain` is the URL host (`www.example.com`), and DS records sit only at delegation points, so a DS miss at a subdomain says nothing.
  - The dns scanner already resolves that domain for DMARC: `lookup_dmarc` calls `self.suffix_list.registrable_domain` under a deadline (`src/scan/dns.rs`). The scan resolves it once and passes it to DMARC, DS and DKIM.
  - When the zone differs from the host, mail shows a `Zone: google.com` row, so the DNSSEC and DKIM rows are never read as the host's.
  - If the suffix list is unavailable, DMARC already falls back to the host. DS and DKIM do the same, and a DS miss then renders `unknown (no suffix list)`, never `no DS`.
- Adds DNSSEC:
  - Rows: `DNSSEC: DS published`, `no DS`, or `failed: <reason>`. The labels describe the observation, not a validation.
  - The WHOIS RDAP value stays as the fallback only when the DS lookup fails. RDAP describes the same registrable domain.
- Adds DKIM:
  - The scan probes TXT at `<selector>._domainkey.<registrable domain>` for a fixed list: `google`, `selector1`, `selector2`, `default`, `k1`, `s1`, `s2`, `dkim`, `mail`.
  - A selector is found when its TXT carries a `p=` tag. An empty `p=` is a revoked key and shows as `<selector> (revoked)`.
  - Rows: `DKIM: google`, `DKIM: none at common selectors`, or `DKIM: failed: <reason>`. More than one found selector reads `DKIM: google +1`; zoom lists them all.
  - The label says "common selectors". A miss is not proof that DKIM is absent.

**DS and DKIM failure semantics and scheduling** (`src/scan/dns.rs`):

- Both use `LensOutcome` (`src/scan/lens.rs`), as `mta_sts` and `tls_rpt` already do, and render through `lens_value` (`src/tui/http.rs`):
  - DS: `Present(count)` / `Absent` / `Failed(reason)`, from one `timed_lookup`.
  - DKIM: `Present(Vec<DkimKey { selector, revoked }>)` when any selector has a key. `Absent` when every selector answered with no key. `Failed(reason)` when none has a key and at least one query failed.
- Each probe is one `timed_lookup` / `txt_at`, bounded by `DNS_TIMEOUT_SECS` (5s).
- The probes join the existing `tokio::join!` of `lookup_dmarc` and `lookup_mail_transport` in the domain branch of the scan. One branch resolves the registrable domain (with DMARC's existing deadline), then runs DMARC, DS and the 9 DKIM probes concurrently. `lookup_mail_transport` stays the other branch.
- So the suffix-list step is no longer DMARC's alone, but it was already on this path; the probes add one 5s query window after it, in parallel with each other.
- The scanner deadline is 30s (`DEFAULT_SCAN_DEADLINE`, `src/scanner.rs`). The domain branch already runs CNAME and CAA sequentially before the join. The probes add no new sequential step beyond that join.

**dns pane** (`src/tui/dns.rs`):

- Order:
  1. Status
  2. PTR
  3. A
  4. AAAA
  5. the rest as today
- In the grid, TXT is one row: `TXT: 17 records (Enter)`. Zoom lists all of them.
- TTL text: `TTL: 1h55m8s (cached)`, from `compact_duration(u64::from(record.ttl_remaining()))`. It is recomputed every frame (already live via `ttl_remaining()`, `src/scan/dns.rs:58-61`; redraw is 250 ms), so the seconds tick.

**Duration formatter:**

- `pub fn compact_duration(secs: u64) -> String` in `src/tui/text.rs`, next to `plural`.
- Units h, m, s, no spaces. Zero units are dropped, except `0s` for zero:

| input (s) | output |
|---|---|
| 0 | `0s` |
| 59 | `59s` |
| 3600 | `1h` |
| 3605 | `1h5s` |
| 10214 | `2h50m14s` |
| 172800 | `48h` (no day unit; S asked for h m s) |

- Used by:
  - DNS TTLs;
  - SOA refresh/retry/expire/minimum (`src/tui/dns.rs:308-314`), so the dns pane reads one way;
  - `TargetPane::format_elapsed` (`src/tui/target.rs:68-81`). That function becomes a call to the shared one, so target's per-scanner times change from `1h 5m` to `1h5m`.
- `pretty::format_duration` (CLI) is not touched (Non-Goals).

**Keys** (`src/tui/mod.rs:231-258`):

| key | grid | zoomed | menu/help open |
|---|---|---|---|
| ← / h, Shift-Tab | prev pane | prev pane | ignored |
| → / l, Tab | next pane | next pane | ignored |
| ↑ / k, ↓ / j, Home | scroll | scroll | menu: move selection; help: scroll |
| Enter | zoom | none | menu: activate |
| p | switch protocol | switch protocol | ignored |
| Esc | open menu | unzoom | close |
| ? | open help | open help | help: close |
| q, Ctrl-C | quit | quit | quit |

- Today Esc quits from the grid. It now opens the menu instead, as btop does, and q and Ctrl-C still quit.
- **Menu:** a centered rounded box over a dimmed grid with entries `Help` and `Quit`. ↑↓/jk select, Enter activates.
- **Help:** a centered box listing the key table above. It is scrollable when the terminal is short.
- **One key table in code:** a `KEY_HELP: &[(&str, &str)]` const holds the table above. Help renders from it, and its tests read it, so the help text and the test cannot drift.
- **State:** both are an `Overlay` enum on `TuiApp`: `None | Menu { selected } | Help { scroll }`. The match arms check the overlay first.
- **Sizing:** the overlay box is computed from the frame area every draw, so a resize recenters it.
- **`?` and Shift:** crossterm reports `?` as `Char('?')` with SHIFT set. `handle_key` matches on `key.code` only (`src/tui/mod.rs`), so the `?` arm needs no modifier guard.
- **Closing:** closing an overlay returns to the view it was opened from. Focus, zoom and each pane's scroll offset are unchanged. Help opened from the menu closes straight to that view, not back to the menu.

**Legend** (`src/tui/pane.rs` + `target.rs`):

- The target pane's top border gets a second, right-aligned title: `┐←↓↑→ hjkl ? help┌`, styled like `bottom_label` (border color, text `LABEL`).
- If the border is too narrow, drop parts in order: first ` help`, then ` hjkl`, then the arrows. `?` always stays.
- Width math uses `Span::width()`. The arrows U+2190-2193 are East Asian Width Ambiguous, and unicode-width (which ratatui uses) counts each as 1 cell.

**Glyphs:**

- Every 🌐 (15 occurrences in `src/tui`) is replaced per row. Each replacement is a default-emoji-presentation glyph that FiraCode Nerd Font Mono lacks. Checked: `fc-list ':charset=<hex>' family | rg -i fira` returns nothing for all six replacements; only U+1F310 matches FiraCode.

| where | from | to |
|---|---|---|
| connectivity status | 🌐 | 📶 U+1F4F6 |
| dns status | 🌐 | 🔎 U+1F50E |
| http status | 🌐 | 📨 U+1F4E8 |
| whois domain | 🌐 | 🔖 U+1F516 |
| security "HTTP Security" | 🌐 | 🧱 U+1F9F1 |
| http timing (zoom) | ⏱ U+23F1 | 🕒 U+1F552 |

- Lint `no_pane_source_uses_a_text_rendered_glyph` in `src/tui/theme.rs` bans U+1F310 and U+23F1 from `tui_sources()`. Each entry carries its own reason comment:
  - U+1F310: FiraCode Nerd Font Mono carries a monochrome globe, which the terminal draws in place of the color emoji.
  - U+23F1: text presentation by default. Only U+FE0F makes it an emoji, and the existing lint bans FE0F.

### Data Model

- `CertificateInfo` gains `issuer_organization: Option<String>` and `issuer_common_name: Option<String>`. The existing `issuer` string stays for the CLI.
- `EmailSecurityAnalysis` (`src/scan/dns.rs`, beside its existing `mta_sts` and `tls_rpt`) gains:
  - `zone: String`, the domain DS and DKIM were queried at (the host when the suffix list was unavailable);
  - `zone_is_registrable: bool`, false on that fallback, so mail renders `unknown (no suffix list)` for a DS miss;
  - `dnssec: LensOutcome<usize>` (DS record count);
  - `dkim: LensOutcome<Vec<DkimKey>>`, where `DkimKey { selector: String, revoked: bool }`.
- `TuiApp` gains `overlay: Overlay`.

### Implementation Plan

Each phase is one commit, `otto ci` green.

#### Phase 0: Prove hickory can query DS records

**Model:** sonnet

- No product code. Write a scratch test using the repo's existing `hickory-resolver` 0.25.2 features to query `DS` for `google.com` and `example.com`.
- If DS needs the `dnssec-ring` (or similar) feature, record which feature and whether it pulls new crates. Then pick between enabling it and a raw `RecordType::Unknown(43)` query.
- **Success criteria:**
  - A DS query for `example.com` returns at least one record. example.com is signed.
  - A DS query for `google.com` returns NoRecordsFound. google.com is unsigned.
  - The result and the chosen query path are pasted into this doc under Phase 0.

**Result (observed 2026-11-06):**

Probe: a throwaway cargo project outside the repo, `hickory-resolver = "0.25.2"` with default features only (`system-config`, `tokio`), `Resolver::builder_tokio()`, system resolver. No DNSSEC feature enabled.

```
example.com. DS: OK 1 records
   example.com. ttl=86400 type=DS data=Unknown { code: DS, rdata: NULL { anything: [9, 67, 13, 2, 201, ...36 bytes] } }
google.com. DS: ERR kind=Proto(ProtoError { kind: NoRecordsFound { query: Query { name: Name("google.com."), query_type: DS, query_class: IN }, soa: Some(Record { name_labels: Name("com."), ... }), negative_ttl: Some(898), response_code: NoError, ... } }) is_no_records_found=true
example.com. Unknown(43): ERR ... NoRecordsFound { query_type: Unknown(43), soa: None ... }
google.com. Unknown(43): ERR ... NoRecordsFound { query_type: DS ... }
```

- **Chosen path: `resolver.lookup(zone, RecordType::DS)` on the existing default features.** No feature change, no new crates, so Phase 4 needs no `Cargo.toml` edit.
- Both success criteria pass: example.com returns 1 DS record (ttl 86400); google.com returns `NoRecordsFound` (`e.is_no_records_found()` is true, NOERROR with the parent SOA, which is the "no DS" case).
- The DS rdata comes back as `RData::Unknown { code: DS, .. }` because the DS parser lives behind the `dnssec-*` features. Presence is all Phase 4 needs (`DS published` / `no DS`), so the rdata is not decoded.
- `RecordType::Unknown(43)` was rejected: it returned `NoRecordsFound` for the signed example.com (a false "no DS"), so it is not equivalent to `RecordType::DS`. `dnssec-ring` was not tried because it is not needed.

#### Phase 1: Glyph swap and lint

**Model:** sonnet

- Apply the glyph table, update the tests that pin the old text (`connectivity.rs:1094`, `whois.rs:423`), and add the lint with its per-glyph reason comments.
- **Success criteria:**
  - `rg -o '🌐|⏱' src/tui | wc -l` prints `0`.
  - Re-adding a 🌐 to any pane makes `no_pane_source_uses_a_text_rendered_glyph` fail. The commit body records that the test was broken on purpose and failed.

#### Phase 2: Duration formatter, TTL and PTR/TXT reorder

**Model:** sonnet

- `compact_duration` and its table test. Wire it into the TTL, SOA and target code.
- dns order: PTR first for name targets. TXT is one count row in the grid and listed in zoom.
- Invert `name_target_renders_ptr_after_the_forward_records` (`src/tui/dns.rs`). Update the two tests that pin TXT rows in the grid: `long_txt_record_is_fit_with_ellipsis_in_narrow_terminals` (render it zoomed) and `a_count_of_one_reads_in_the_singular` (its `TXT: 1 record` row stays, with no value row under it).
- **Success criteria:**
  - `compact_duration(10214) == "2h50m14s"` plus every table row above.
  - In a grid render of a name target, the `PTR:` row index is less than the `A:` row index. No TXT record value appears in the grid; every value appears in zoom.
  - A TTL row rendered at `queried_at` and at `queried_at + 1s` differs by one second (`TTL: 8s` -> `TTL: 7s`).

#### Phase 3: Keys, Esc menu, help overlay, legend

**Model:** opus

- Add h/l, the `Overlay` state, the menu and help rendering, and the legend on the target top border.
- Fix the stale comment at `layout.rs:290`.
- Make `ZOOM_FOOTER` include j/k and `?`.
- **Success criteria:**
  - `h`/`l` move focus exactly as `←`/`→` do, both in the grid and zoomed. `j`/`k` still scroll; the existing scroll tests pass unchanged.
  - Esc in the grid shows a frame containing `Help` and `Quit`. Enter on `Quit` sets `should_quit`. Esc again closes the menu without quitting.
  - `?` shows a frame containing every `KEY_HELP` entry. A second test asserts `KEY_HELP` names `h`, `l`, `j`, `k`, `?`, `p`, `Esc`, `Enter` and `q`.
  - Opening and closing an overlay while zoomed on a scrolled pane leaves zoom, focus and the scroll offset unchanged.
  - At 200x56 the target top border contains `┐target┌` and `←↓↑→ hjkl ? help`. At 80x24 it still contains `?`.

#### Phase 4: Single pane table, cert and mail panes, grid rebalance

**Model:** opus

- One pane table used by `TuiApp::new` and `create_default_layout`.
- Add `cert.rs` and `mail.rs`, each with a status row. Move the cert and email blocks out of `security.rs`, and fold grade/issues into its status row.
- Add `issuer_organization`/`issuer_common_name` via OpenSSL `entries_by_nid`, and the distrust table with its verified sources.
- Add DS and DKIM probing in the dns scanner as `LensOutcome`s, on the path proven in Phase 0, joined into the existing DMARC/mail-transport `tokio::join!`. The DS zone comes from `SuffixList::registrable_domain`.
- Set `DEFAULT_GRID_COLS` to 5. Add new widths in `grid_layout`, `pane_border` entries for `cert` and `mail`, and updates to the pane-set test constants (`SCROLLING_PANES`, `PANE_TITLES`, the title count, `testing.rs:127-132`).
- **Success criteria:**
  - A fixture TLS result with a `CN=WE2, O=Google Trust Services` issuer renders `CA: Google Trust Services (WE2)` as the first row after `Status:` in `cert`.
  - A fixture certificate with `O=Entrust, Inc.` and `notBefore` after its distrust date renders the CA row with `fg_of == theme::BAD` and ` (distrusted CA)`. A fixture with `O=Google Trust Services` does not.
  - A `tls` scanner in `Failed` state with a kept old result renders `cert`'s status row as failed.
  - An IP target renders mail's `not applicable (IP target)` row and sends no DS or DKIM query.
  - `mail` renders each `LensOutcome` state for DNSSEC (`DS published`, `no DS`, `failed: …`) and DKIM (`google`, `none at common selectors`, `failed: …`, `(revoked)`), one fixture each.
  - The DS zone for target `www.tatari.tv` is `tatari.tv` (fixture suffix list, as in `psl.rs`'s tests).
  - The grid draws 11 titles, and at 80x24 every pane still draws its title.

## Acceptance Criteria

- [ ] At 200x56 against google.com, `bin/snap.py google.com --bin target/debug/scan --wait 20 --ansi snap.ansi` shows, with dns `resolved` and security `analyzed` in the capture:
  - dns's top rows are `Status, PTR, A, AAAA`;
  - cert's first row after `Status:` is its `CA:` row;
  - mail shows SPF, DMARC, DNSSEC and DKIM rows;
  - the dns and security overflow counts (`↓ N more`) are each lower than on main. Overflow itself is allowed (G1).
  - Observed on main (v0.6.0, this exact command, 2026-11-06): dns `🌐 Status: resolved`, then `A: 1 record, TTL: 237s (cached)`; dns `↓ 20 more`, security `↓ 20 more`; cert and mail panes do not exist.
- [ ] `rg -o '🌐' src/tui | wc -l` prints `0`.
  - Observed on main: `15`.
- [ ] In the dns grid for google.com, TTLs read `NhNmNs`-style and no TXT value appears.
  - Observed on main: `TTL: 8s (cached)`, and TXT values listed (snap capture).
- [ ] Esc in the grid opens a menu containing `Help` and `Quit` and does not quit. `h`/`l` move focus. `?` opens help listing every key, including `p`.
  - Observed on main: Esc quits (`src/tui/mod.rs:237-240`). `rg -n "Char\('(h|l|\?)'\)" src/tui` prints nothing. `p` is handled (`src/tui/mod.rs:250`) and listed nowhere.
- [ ] The DNSSEC and DKIM rows render all three `LensOutcome` states (Phase 4 fixtures).
  - Observed on main: security shows `DKIM: not checked (needs selector)` (`security.rs:564`, test at `security.rs:981`); DNSSEC appears only in the whois pane.

## Resolved Decisions

- 2026-11-06, S: TTL format is `2h50m14s` (h, m, s, no spaces). Zero units are dropped, so `1h` and not `1h0m0s` (author call: the example had no zeros). There is no day unit.
- 2026-11-06, S: help copies btop. Esc opens a menu, Help is in it, and `?` goes straight to help. This replaces a permanent help bar (P's ask is met by the legend + menu).
- 2026-11-06, S: the key legend goes on the top edge of the upper-left pane (target), right-justified.
- 2026-11-06, S: some overflow is fine. The aim is the most useful information on the page; scrolling and zoom are the fallback. The acceptance criteria assert priority rows and less overflow, not zero overflow.
- 2026-11-06, author: h/l mirror ←/→ and j/k keep scrolling. Each hjkl key does exactly what its arrow does, so the legend `←↓↑→ hjkl` is literally true. Spatial movement would take scrolling off j/k.
- 2026-11-06, author: the distrusted-CA list is a static table in code. scan has no config system, and browser distrust changes a few times a year. If it needs to change faster than releases, move it to config then.
- 2026-11-06, author: room comes from width, not height. Row 0's height is fixed by target's 12 scanner rows; connectivity gives up 30% of its width to cert.
- 2026-11-06, author (panel round 1): the distrust mark is a heuristic on what scan sees (presented issuers, leaf `notBefore`), labelled "distrusted CA", not a browser verdict. Matching Chrome exactly needs path building and SCT parsing, which this plan does not add.
- 2026-11-06, author (panel round 1): DS is queried at the registrable domain and labelled as an observation (`DS published` / `no DS`). A failure or a missing suffix list is never shown as unsigned.

## Alternatives Considered

### Cert pane only

- **Description:** move only the cert block out of security.
- **Pros:** one new pane.
- **Cons:** security is still 32 rows in 20, with the email posture below the fold.
- **Why not chosen:** it leaves the most rows off the page (G1).

### Shrink row 0's height

- **Description:** take height from connectivity's row and give it to row 2.
- **Pros:** dns, traceroute and security all grow.
- **Cons:** target shares row 0 and needs exactly 12 rows, so it would start scrolling unless its scanner list is compacted, which nobody asked for.
- **Why not chosen:** width on row 0 is free; height is not.

### A fourth grid row

- **Description:** add cert and mail as a new row.
- **Cons:** every other pane loses height, and dns gets worse.
- **Why not chosen:** it puts fewer dns rows on the page (G1).

### Permanent footer help bar (P's literal ask)

- **Description:** a one-row footer on the main page listing the keys.
- **Cons:** it costs every pane a row of height.
- **Why not chosen:** S chose the btop menu plus a border legend, which costs no height.

### Exact Chrome distrust matching

- **Description:** build the verified path to a trust-store root and read the leaf's SCT timestamps, then apply each Chrome action's exact rule.
- **Pros:** the mark would match what Chrome does.
- **Cons:** needs a trust store, path building and SCT parsing; scan today connects with verification off.
- **Why not chosen:** K asked for distrusted CAs to look different, not for a browser verdict. The heuristic covers that and says what it is.

## Technical Considerations

### Dependencies

- None new, unless Phase 0 shows DS queries need a hickory feature. That would be a feature on an existing direct dependency, recorded in Phase 0.

### Performance

- DKIM adds 9 TXT queries per scan and DS adds 1. They run concurrently inside the existing DMARC/mail-transport join, each bounded by the 5s DNS timeout, so they add no sequential step.
- The suffix-list lookup for the DS zone is a disk-cache hit after the first fetch.
- The overlay draws only when open.

### Security

- Read-only DNS lookups against the target's public zone. No new network surface beyond the queries above and the suffix-list fetch whois already makes.

### Testing Strategy

- Per-pane `TestBackend` tests via `src/tui/testing.rs`.
- Key tests via `TuiApp::handle_key` + `frame_text`.
- `LensOutcome` rendering tests per state for DNSSEC and DKIM.
- Each lint is broken on purpose once to prove it bites.
- Visual check via `bin/snap.py` at 200x56 and 80x24 after Phases 3 and 4. A live CA name (`WE2`) is recorded as an observation only; the exact string is asserted on fixtures.

### Rollout Plan

- Single repo, no cross-repo blast radius.
- Ship with `bump release` (ungated) after Phase 4. Then verify `scan --version` and run a snap of the installed binary.

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| dns and security still overflow on targets with many records or headers | High | Low | Accepted (G1). Priority rows lead, the overflow marker shows, and zoom shows all. |
| DKIM common-selector probe reports "none" for a domain that has DKIM | High | Low | The label says "none at common selectors", never "missing". |
| Distrust dates are wrong | Med | Med | Each entry is verified against a cited Chrome/Mozilla source in Phase 4. |
| Distrust heuristic differs from Chrome on an edge case (cross-signed path, SCT date differs from notBefore) | Med | Low | Labelled "distrusted CA", not a browser verdict (Non-Goals). |
| Suffix list unavailable, so DS zone may be a subdomain | Low | Low | A miss then renders `unknown (no suffix list)`, never `no DS`. |
| 5 columns in row 1 truncate at 80x24 | High | Low | Already truncates at 4 columns. Rows end in `…`, and zoom shows all. |
| Replacement glyphs render 1 cell in some terminal | Low | Low | Default-emoji-presentation picks only. The existing FE0F lint stays. |

## Review Panel Round 1

Synthesis: `~/.cache/review-panel/runs/b8wAfdlM/synthesis.md` (Gemini Architect, Codex Staff Engineer).

Folded in:

- Issuer fields come from OpenSSL `entries_by_nid`, and the data path is `TlsData.certificate_chain` (both seats).
- DKIM and DS use `LensOutcome`, with a defined "found", and join the existing DMARC/mail-transport join under the 5s timeout (both seats).
- `DEFAULT_GRID_COLS` 4 -> 5 named in Phase 4 (Staff).
- DS zone is the registrable domain, labelled as an observation; failure is never "unsigned" (Staff).
- Distrust rule reworded as a heuristic on presented issuers; chain shown "as sent", no root claim (Staff).
- `p` in the key table and help test; overlay close semantics (Staff).
- Status rows for cert and mail (Staff).
- Acceptance criteria wait for populated panes and pin `WE2` only on fixtures; a G6 criterion added (Staff).
- Legend arrows are 1 cell; the ⏱ reason is text presentation, not FiraCode (synthesis).

Resolved by S:

- dns still overflows by about 2 rows (Staff). S: "we can have some overflow". G1 and the acceptance criteria now assert priority rows and less overflow.

Pushed back:

- Static bad-CA table breaks the config standard (Architect): already a Resolved Decision; config is a Non-Goal.
- Kill switch for DKIM probing (Architect): that standard is for risky writes; these are read-only DNS queries.
- Target elapsed-time format change and the ⏱ swap as unrequested scope (Staff): the formatter keeps one duration format across the panes, and the ⏱ swap is forced by the FE0F ban. Both are disclosed above.
- Release/recovery, audit and shakedown missing from Rollout (Staff): the standing pipeline covers them for every plan.

## Pass Log

- Pass 1, Draft (2026-11-06, session `3387b446`): research brief from `plan:design-research`, doc drafted.
- Pass 2, Correctness (same session): fixed the security row budget, which summed to 22 and not 20.
- Review panel round 1, then passes 3-5 (2026-11-06, session `57cb8d0a`). The earlier session stopped after pass 2 and listed passes 3-5 as next.
- Pass 3, Clarity:
  - `EmailSecurity` -> `EmailSecurityAnalysis`, the struct's name in `src/scan/dns.rs`.
  - Phase 2 names the tests it changes, in place of line ranges.
  - mail's data source and first row are named; "Row 1" no longer collides with grid row 1.
  - The help table is one `KEY_HELP` const; Phase 3's "a key added to the handler fails the test" was not testable and is replaced.
  - Security's grade and issue inputs are stated as unchanged.
- Pass 4, Edge cases:
  - IP targets: mail shows `not applicable`, and no DS or DKIM query runs.
  - cert with no certificate, or an issuer with no O=/CN=.
  - The registrable domain is resolved once and shared with DMARC, which already looks it up. The panel-round text that put the suffix list on its own was wrong.
  - A `Zone:` row when the zone differs from the host.
  - `?` arrives with SHIFT set; the match ignores modifiers.
  - Overlay recenters on resize; several DKIM selectors collapse to `+N`.
  - AC1 baseline re-measured on a rebuilt v0.6.0 binary with `--wait 20`. The old `target/debug/scan` was v0.5.10-1.
- Pass 5, Excellence: checked fit with in-house parts (`status_label`, `LensOutcome`, `lens_value`, `SuffixList`, the theme lints) and the Rust module rule (`tls.rs` + `tls/distrust.rs`). No design change.

## Open Questions

- [ ] None.

## References

- Slack thread: https://tatari.slack.com/archives/C01FXF7P3ST/p1793999876032139
- v0.6.0 commit `297abcd`, `bin/snap.py`
- Review panel round 1: `~/.cache/review-panel/runs/b8wAfdlM/synthesis.md`
