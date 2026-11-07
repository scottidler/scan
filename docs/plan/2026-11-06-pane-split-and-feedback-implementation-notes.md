## Phase 0: Prove hickory can query DS records
### Design decisions
- Query DS with `RecordType::DS` on default hickory-resolver 0.25.2 features — docs/plan/2026-11-06-pane-split-and-feedback.md, Phase 0 — works for signed (record) and unsigned (`NoRecordsFound`) zones and adds no dependency.
- Treat DS rdata as opaque (`RData::Unknown`) — Phase 4 only needs presence/absence, and decoding needs a `dnssec-*` feature.
### Deviations
- None.
### Tradeoffs
- `RecordType::DS` vs raw `RecordType::Unknown(43)` — Unknown(43) returned `NoRecordsFound` for signed example.com (false negative), so it is unusable.
- Default features vs `dnssec-ring` — not needed, so no new crates.
### Open questions
- None.

## Phase 1: Glyph swap and lint
### Design decisions
- Each of the 15 🌐 and 3 ⏱ mapped by pane to the doc's table (whois 6 -> 🔖, dns 2 -> 🔎, security 2 -> 🧱, connectivity 2 -> 📶, http 3 status -> 📨, http 3 timing ⏱ -> 🕒) — src/tui/*.rs — every occurrence fit a row, none ambiguous.
- Lint bans the glyphs by `char` escapes (`'\u{1F310}'`, `'\u{23F1}'`) — src/tui/theme.rs:no_pane_source_uses_a_text_rendered_glyph — so theme.rs, which is scanned by `tui_sources()`, does not trip itself.
### Deviations
- None. (The 15-count in the doc covers 🌐 only; the 3 http ⏱ occurrences are the additional zoom-timing row.)
### Tradeoffs
- Reason comments inline per banned entry vs a shared doc comment — matches the doc's "each entry carries its own reason".
### Open questions
- None.

## Phase 2: Duration formatter, TTL and PTR/TXT reorder
### Design decisions
- `compact_duration` lives next to `plural` (src/tui/text.rs:compact_duration): one shared h/m/s formatter, no day unit, `0s` for zero.
- `TargetPane::format_elapsed` is a one-line call to it (src/tui/target.rs). Target elapsed times read `1m30s`, and `3661s` reads `1h1m1s` (it used to drop seconds past an hour).
- PTR is emitted once, right after Status, for IP and name targets alike (src/tui/dns.rs:build_dns_result_lines). The old trailing `ptr_lines` call is gone.
- TXT is a count row only in the grid (`TXT: N records (Enter)`, no TTL on that row). Zoom keeps the `TXT: N records, TTL: ...` header and lists every value. The grid-only `google-site-verification=...` / `MS=...` abbreviation and its two constants were dead after this, so they are removed.
- Each new test was broken on purpose and failed, then the code was restored: `compact_duration` zero branch, `ttl_span` hard-coded to 8, the TXT zoom gate (`if true`), PTR moved to the end.
### Deviations
- The two TXT clip tests are renamed (`long_txt_record_wraps_whole_when_zoomed_in_narrow_terminals`, `long_multibyte_txt_record_wraps_by_display_width_when_zoomed`) and assert wrapping, not an ellipsis. Zoom wraps every line (`to_rows`), so a zoomed TXT value is never clipped, and the old names would lie. Fixtures are longer so they exceed the 108x40 inner width.
- Existing assertions that pinned `300s`, `1200s`, `7200s`, `1209600s` now read `5m`, `20m`, `2h`, `336h`. The doc's table applies the shared formatter to every TTL and SOA timer.
### Tradeoffs
- Zoom TXT header keeps its TTL vs dropping it everywhere: zoom already shows each record's TTL.
- The TTL test back-dates `queried_at` by 292s and 293s vs sleeping a second: deterministic, no wait.
### Open questions
- None.

## Phase 3: Keys, Esc menu, help overlay, legend
### Design decisions
- The menu, help and `KEY_HELP` live in a new module (src/tui/overlay.rs): `Overlay`, `MenuItem`/`MENU_ITEMS`, `help_max_scroll`, `render`. mod.rs stays the event loop.
- `handle_key` checks `q`/Ctrl-C first, then matches on `self.overlay` and hands off to `handle_menu_key`, `handle_help_key` or `handle_dashboard_key` (src/tui/mod.rs). Keys the table marks ignored are logged at trace and dropped.
- `?` with the menu open goes straight to help. The table leaves this cell blank; `?` opens help from every other view, so it does here too. Closing help then returns to the dashboard, not the menu.
- Help's Down is clamped against the box as last drawn (`TuiApp.frame_area` + `overlay::help_max_scroll`), and `render` clamps again on draw. Without the key-time clamp, extra Downs pile up and the first Up does not move. This is the same bug the pane scroll already guards against.
- Dimming recolors every cell's fg with `theme::dimmed` (RGB x0.35; a non-RGB color becomes `MUTED`). It does not use the terminal DIM attribute. The fg colors stay in the palette and are pinned by `dimmed_scales_rgb_toward_black_and_mutes_the_rest`.
- Legend: a `Pane::shows_key_legend` trait method (default false, `TargetPane` true). `draw_rows` adds `pane::key_legend(width, title, focused)` as a right-aligned `title_top`. The form that fits is the first `KEY_LEGENDS` entry with `title width + 1 gap + legend width <= width - 2`. ratatui 0.29 draws the right title over the left one when they overlap, so the fit check is ours. `create_block`'s title became `title_line` so the fit check can measure it.
- `bottom_label` is now `pub(crate)`, so help's overflow marker matches the panes' markers.
- Removed the stale `// MUTED: Gray until the theme lands (Phase 2).` comment from `render_zoomed`. The theme has landed and the line restated the code. `ZOOM_FOOTER` is now `Esc back · ←/→ h/l pane · ↑/↓ j/k scroll · ? help`.
- I broke each new test on purpose, saw it fail, and restored the code. The breaks:
  - dropped `Char('l')` and, separately, `Char('h')` from the focus arms;
  - removed `Char('j')` from the layout scroll arm;
  - made grid Esc quit;
  - removed `should_quit` from menu Quit;
  - made help render one row short;
  - guarded `?` on empty modifiers;
  - dropped `q` from `KEY_HELP`;
  - made `open` unzoom;
  - turned off target's `shows_key_legend`;
  - dropped the `?`-only legend form (caught by the pane unit test; the 80x24 app test still fits `←↓↑→ ?`);
  - reverted `ZOOM_FOOTER`.
### Deviations
- `esc_while_not_zoomed_quits_and_q_quits_from_zoom` (src/tui/layout.rs) is inverted and renamed to `esc_while_not_zoomed_opens_the_menu_and_q_quits_from_zoom`. Esc in the grid no longer quits.
- Two target tests asserted `!out.contains('↓')` to mean "no overflow marker". The legend's arrows now contain `↓`, so they assert `!out.contains("↓ ")`, which is the marker's actual shape (`↓ N more`): `tall_pane_shows_every_scanner_the_summary_and_no_marker`, `target_at_200x55_shows_every_row_and_the_protocol_on_the_status_row`.
- The legend draws on target in zoom as well as in the grid. The doc scopes it to the target top border and does not separate the two.
- The doc points at pane.rs + target.rs for the legend. It is a trait method plus a `draw_rows` hook: same effect, correct seam.
### Tradeoffs
- New key/overlay tests sit in layout.rs's test module, beside the existing app-level Esc/zoom tests, rather than in mod.rs. They need the `overflowing_state`/`frame_text`/`titles` fixtures defined there.
- A recolored fg for dimming vs `Modifier::DIM`: the recolor is deterministic in tests and in the snap PNG renderer, and DIM rendering varies by terminal.
- Menu entries carry no key hints (`Help`, `Quit` only). That matches the doc and avoids a second source of key names beside `KEY_HELP`.
### Open questions
- At 0.35 the dimmed dashboard is darker in the raw ANSI (e.g. `119,202,155` -> `42,71,54`). Color emoji are glyphs and cannot be dimmed, so they stay bright behind the box. Confirm the strength on your terminal.

## Phase 4: Single pane table, cert and mail panes, grid rebalance
### Design decisions
- One pane table — src/tui/mod.rs:panes — `create_default_layout` iterates it and `TuiApp::new` calls `create_default_layout`, so the panes are listed once. Table order is focus order: cert follows connectivity, mail follows geoip, and traceroute's Left is still dns.
- The DNS email posture moved behind one seam — src/scan/dns.rs:DnsScanner::email_security — which takes the resolver and returns `None` before any query when the target has no domain or its URL host is an IP literal. `mail_zone` resolves the registrable domain once, under DMARC's old deadline; `lookup_dmarc` now takes the registrable domain as a parameter instead of resolving it. One `tokio::join!` branch runs zone, then DMARC + DS + the 9 DKIM probes concurrently; `lookup_mail_transport` is the other branch.
- `mail_zone` treats "suffix list names no registrable domain" (`Ok(None)`: localhost, a bare suffix) like "suffix list unavailable": zone = host, `zone_is_registrable = false` — src/scan/dns.rs:mail_zone — so a DS miss at a name that is not a delegation point never reads `no DS`.
- DS is counted by `record_type() == DS` on the answer, rdata left opaque — src/scan/dns.rs:lookup_ds — per the Phase 0 path (`RecordType::DS`, default features).
- DKIM probes run through `futures::future::join_all` — src/scan/dns.rs:lookup_dkim — and `dkim_outcome` is pure. A failure reads `<first reason> (N of 9 selectors)`, so one timed-out selector is not read as all of them.
- `tls.rs` declares `mod distrust;` (private) and re-exports `distrust_of`, `DistrustedCa`, `DISTRUSTED_CAS` — src/scan/tls/distrust.rs. Matching is ASCII-case-insensitive equality on the issuer `O=`, and `leaf.not_before` (UTC date) `> distrusted_after`.
- cert rows — src/tui/cert.rs — Status, CA, `Valid: yes · N days`, Subject, Key, SAN, `Chain (as sent):` + one row per presented certificate (its subject CN). Status and CA rows wrap rather than clip, so a long CA name stays whole in the 30% column. A chain row reads `(distrusted CA)` when that certificate's issuer `O=` matches, judged by the leaf's `notBefore`. Zoom replaces the short chain with the full per-certificate detail moved from security.
- Empty chain: the status row reads `analyzed · no certificate[: <first certificate error> | handshake failed]` and nothing else draws.
- mail rows — src/tui/mail.rs — Status, [`not applicable (IP target)`], [`Zone:`], SPF, DMARC, (zoom: MTA-STS, TLS-RPT), DNSSEC, DKIM, (zoom: one `selector:` row per key), MX, then the SPF and DMARC record text. `no DS` is WARN, `unknown (no suffix list)` MUTED. A failed DS lookup appends ` · RDAP: signed|unsigned` from the whois result when it has one.
- security — src/tui/security.rs — the status row is `🔒 Status: analyzed · <grade> · N issues`, the issue bullets sit directly under it, and PFS/OCSP share `🔰 PFS: yes · OCSP: not checked`. The `📜 Cert: validating...` pending row went with the certificate block.
- New glyphs: `📜` (cert status), `📧` (mail status), `🔰` (PFS row). All are default-emoji-presentation, and the theme lints pass. New border colors: cert `#a53b7a`, mail `#5a8a2e`.
- The overflow marker drops ` more` when `┘↑ N ↓ M more└─` does not fit the box — src/tui/pane.rs:RowView::marker_within. Without it, 16-column row-1 cells at 80x24 cut `↑ N` off the left edge.
- I broke each success-criterion test on purpose, saw it fail, then restored the code:
  - CA row moved after Valid;
  - `distrust_of` forced to `None`;
  - cert status hard-coded `analyzed`;
  - the IP-literal guard in `email_security` disabled (the URL-IP case then queried);
  - the `not applicable (IP target)` text changed;
  - `no DS` and `(revoked)` text changed;
  - `mail_zone` returning the host;
  - `DEFAULT_GRID_COLS` back to 4.
### Deviations
- `lens_value_or(outcome, present, absent)` added in src/tui/http.rs, and `lens_value` delegates to it. DNSSEC and DKIM need their own Absent text (`no DS`, `none at common selectors`). Same effect, correct seam.
- `EmailSecurityAnalysis::fixture()` (`#[cfg(test)]`) replaces repeated literals in tests now that the struct has 10 fields.
- The `Zone:` row compares the zone with the host parsed from `AppState.target` (`Target::parse`). This adds no field to the Data Model.
- Tests moved out of security.rs, not copied:
  - cert.rs took the CN, expiry, SAN and chain-zoom tests;
  - mail.rs took the MTA-STS/TLS-RPT tests;
  - `Expires: N days` is now cert's `Valid: yes · N days`;
  - `Issues: N` assertions now read the status row's `N issue(s)`.
- `dkim_reads_not_checked_and_dmarc_reads_configured` (security.rs) pinned DKIM as `not checked`. It is removed, and `mail.rs:dkim_renders_a_selector_none_failed_and_revoked` covers the probed states in its place.
- `whois.rs:domain_from_host_is_intact_at_200x55` is renamed to `domain_from_host_leads_its_row_at_200x55_and_is_whole_in_zoom`.
  - At 20% width (40 cols) `Domain: tatari.tv (from www.tatari.tv)` no longer fits, so the test now asserts the row's lead and the whole text in zoom.
  - The doc only checked that `client transfer prohibited` fits.
  - Wrapping the Domain row would break `long_domain_is_fit_with_ellipsis_in_narrow_terminals`, so I left it as is.
- `http.rs:long_redirect_target_url_is_fit_on_its_own_row` now asserts the redirect source row as clipped. The 108x40 http cell is narrower.
- The overflow-marker change (pane.rs) is not in the doc. It is forced by the 5-column row.
- `scan/tls.rs:chain_of_leaf_and_two_intermediates_counts_three_certificates` now reads the cert pane's `Chain (as sent): 3 certificates`.
- Distrust entries that are in the doc's list but scoped down from what was fetched:
  - Symantec: `O=` values are those of the brands Chrome's post names (Symantec, VeriSign, GeoTrust, thawte/Thawte, Equifax), checked against the roots in Chromium's `net/data/ssl/symantec/roots` (tag 100.0.4896.60). Left out from that same directory:
    - `TC TrustCenter GmbH` / `TC TrustCenter for Security in Data Networks GmbH`: the post does not name the brand;
    - `RSA Data Security, Inc.`: not a Symantec name;
    - `The USERTRUST Network`: Sectigo's root, cross-signed, and including it would mark every Sectigo chain.
  - WoSign/StartCom: `distrusted_after: None`. The post's 2016-10-21 cutoff was the first stage, it says the stages culminate "in the full distrust", and Chromium's blocklist lists the roots outright. `Certplus` (a cross-signed root in that blocklist group) is left out.
  - Camerfirma: the source is Chromium's blocklist README ("trust ... was fully removed"), not a Google blog post; I found no Chrome blog post to fetch for it.
### Tradeoffs
- Exact `O=` match vs Chrome's own "Organization contains Entrust or AffirmTrust" guidance: exact values come straight from the fetched root names and cannot match an unrelated org that happens to contain the word.
- `Target::parse` on every frame for the Zone row vs adding a `host` field: parse is pure and already in-house, and its debug log is off at the default level.
- Wrapping the CA row (one extra row at 80x24) vs clipping: the CA row is G5's point, and a clipped CA name hides the issuing CA's CN.
- DS presence only vs decoding: no `dnssec-*` feature, no new crates, per Phase 0.
### Open questions
- TC TrustCenter (Symantec-acquired, in Chromium's Symantec roots set) is not in the table. Add it?
- The table matches on issuer `O=` only. If Entrust or another distrusted owner issues new certificates under its own `O=` via a cross-signed path to a trusted root, scan marks them anyway. That is the heuristic the doc accepts. I have not verified whether such intermediates exist today.
- `no DS` renders WARN. Should an unsigned zone be MUTED instead? It is common, and google.com is unsigned.

## Phase 4 (audit follow-up)
### Design decisions
- `Target::dns_name` — src/target.rs — returns the host as a DNS name, or `None` for an IP host, bare or in a URL. The dns scanner's forward branch and `email_security` both key on it. Before, `https://1.1.1.1/` ran A/MX/TXT/… lookups on the literal `1.1.1.1` and got a non-reverse-only result, so mail showed only its status row. Now an IP-URL target is reverse-only, like a bare IP: no MX, TXT, DMARC, DS or DKIM query goes out (`scan::dns::tests::an_ip_url_target_gets_no_forward_lookups`).
- The mail pane's `not applicable (IP target)` row also keys on the target's host — src/tui/mail.rs:has_ip_host — not only on the result's shape.
- Distrust matching is now ASCII-case-insensitive *containment* of a listed value in the issuer `O=` — src/scan/tls/distrust.rs:distrust_of. That is how both dated Chrome posts word their own guidance ("Organization (O) ... contains"). I re-fetched the sources on 2026-11-07 and copied their named values verbatim:
  - Entrust: `Entrust`, `AffirmTrust`;
  - Chunghwa Telecom: `Chunghwa Telecom`, `行政院`;
  - NetLock: `NETLOCK Ltd.`, `NETLOCK Kft.`.
  - Symantec, WoSign/StartCom and Camerfirma: their posts name no `O=` values, so they keep the root `O=` values read from Chromium's certificates.
- The CA row reads `(distrusted CA)` when *any* presented certificate's issuer matches, judged by the leaf's `notBefore` — src/tui/cert.rs:ca_line — per the doc's "the issuer_organization of each presented certificate".
- `DNSSEC: no DS` is MUTED, like the other "nothing there" mail rows.
- Enter while zoomed is a no-op — src/tui/mod.rs:handle_dashboard_key — per the key table. Before, it re-zoomed and reset the zoomed scroll.
- I broke each fix on purpose, saw its test fail, then restored it:
  - mail IP-URL gate removed;
  - the dns forward branch back on `target.domain` (the test then queried the system resolver);
  - `dns_name`'s URL arm removed;
  - `NETLOCK Ltd.` dropped from the table;
  - containment reverted to equality;
  - the CA row checking only the leaf;
  - `no DS` back to WARN;
  - the zoomed-Enter guard removed.
### Deviations
- The doc says `organizations` lists every O= value; it is now a list of values an `O=` must contain. This matches the cited sources' own wording. The struct and field names are unchanged.
- Doc edits (Status stays Implemented):
  - The Bad CA bullet gains the Camerfirma source exception.
  - The row-budget sentence now says the folded grade is the TLS grade, and Observatory's grade keeps its own `HTTP Grade:` row.
### Tradeoffs
- Containment vs exact equality: containment follows Chrome's FAQ and catches spellings such as `Entrust Limited` or `Chunghwa Telecom Co. Ltd`. Short root values (`Thawte`, `Equifax`) now also match any `O=` that contains them; I judged that acceptable for a labelled heuristic.
- Skipping forward lookups for an IP-URL host vs only hiding its mail rows: the literal's forward answers were never meaningful, and skipping them is what makes "no MX/DS/DKIM query" true.
### Open questions
- TC TrustCenter (from Phase 4) is still out of the table, pending your call.
