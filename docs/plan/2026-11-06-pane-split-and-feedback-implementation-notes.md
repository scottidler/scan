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
