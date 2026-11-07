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
