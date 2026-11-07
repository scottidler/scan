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
