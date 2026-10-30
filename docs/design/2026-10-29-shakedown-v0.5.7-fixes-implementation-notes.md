## Phase 1: Honest small labels

### Design decisions
- Sparkline title drops `scale 0-N` unless a successful sample is visible; `← Ns` stays. File: `src/tui/connectivity.rs` full-mode title. Why: a scale for zero replies was the fallback 1ms, not a measurement.
- One `family_state_text(state, view, visible, StateForm, checking_text)` serves full and compact rows; a Disconnected family shows `family_failure_label` in both, so compact no longer reads `v6 ---`. File: `src/tui/connectivity.rs`. Why: one function kills the class.
- Ports: the progress block and its three constants are deleted. A Running refresh draws neither `Progress:` nor `Scanned: completed` (the retained result would make `completed` a lie); the header's `↻ refreshing` carries the state. File: `src/tui/ports.rs`.
- Cert CN: the 25-char cap and `CN_DISPLAY_MAX_LENGTH` are removed; `fit_line` marks any cut with `…`. File: `src/tui/security.rs:common_name_display`.
- Security Features: `PFS: n/a` (Gray) when the handshake failed; `OCSP: not checked` (Gray) always, so the `ocsp` field was dropped from the pane's data extraction. File: `src/tui/security.rs`. Why: stapling is never collected.
- User labels: `CspStrength::label`, `CorsSecurityLevel::label`, `PrivacyLevel::label` beside their enums; HTTP grade uses `SecurityGrade::as_str`. The HTTP-grade color match keyed on the string `"APlus"` and now keys on `"A+"`. Files: `src/scan/http.rs`, `src/scan/whois.rs`, `src/tui/security.rs`.
- `TracerouteHop::is_silent()` (no probe answered) backs `TracerouteData::silent_hops()` and `last_reply_hop`; the TUI hop row uses `is_silent` and `pretty.rs` calls `silent_hops()`, replacing the `packet_loss > 0.5` count and its constant. Files: `src/scan/traceroute.rs`, `src/pretty.rs`, `src/tui/traceroute.rs`.
- Null MX: `is_null_mx` matches exactly one record, priority 0, exchange `.`; renders `MX: none (null MX)` in Gray. File: `src/tui/dns.rs`.
- First-render log moved into `TuiApp::run` after the first `terminal.draw`. `run` delegates to `run_with_keys(.., next_key)` so a test can inject the key source; `with_startup(Instant)` keeps `startup_to_render` measured from process start. Files: `src/tui/mod.rs`, `src/main.rs`.

### Deviations
- The doc says the TUI uses `silent_hops()`, but the TUI draws per-hop rows and has no count until Phase 7 collapses silent runs. The TUI shares the `is_silent` predicate instead (same effect, correct seam); Phase 7 can call `silent_hops()` when it adds run rows.
- The log line is now `[tui] First TUI render completed` (was `[main]`) because `TuiApp` emits it. Message text unchanged.
- Compact Connectivity uses the full failure label, not a shortened one, because the criterion needs the same text in both modes. A very narrow pane cuts it with `fit_line`.

### Tradeoffs
- Injecting the key source (`run_with_keys`) vs polling the real terminal in a test: only injection can assert "logged before any key is read".
- Dropping the `Scanned:` line during a refresh vs a new word: the header already says `↻ refreshing`; a second label repeats it.
- Test-only capture logger via `log::set_logger` in `src/tui/mod.rs`: safe while no other lib test installs a logger; it needs a guard if one ever does.

### Open questions
- None.

Evidence: each new test was run with its fix mutated away and failed (scale title, shared no-route text, ports progress, CN cap, PFS, OCSP, CSP/CORS/grade labels, privacy label, silent-hop count, null MX, first-render log); sources were then restored.
