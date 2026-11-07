# Implementation notes: Distrust config overlay, issuer-CN matching, eMudhra

Design doc: `docs/plan/2026-11-07-distrust-config-and-emudhra.md`

## Phase 1: Issuer-CN matching, owned table, eMudhra entries

### Design decisions
- Three eMudhra entries, not two (`src/scan/tls/distrust.rs:builtin_distrusted_cas`): G3 root undated, G1 root dated 2026-11-16, compromised intermediates undated. The Phase 1 bullet says "the two eMudhra entries", but the Data Model table and review finding M1 specify three, and the phase's own test list includes `emsign_compromised_intermediates_are_distrusted_as_the_leaf_issuer`. The table wins; the bullet predates M1.
- The eMudhra comments quote the Google post verbatim, fetched 2026-11-07 (`builtin_distrusted_cas`): "removed emSign ECC Root CA - G3 (the root certificate that signed the compromised CA certificates) from the Chrome Root Store", the Nov 4 update's "validating to CN= emSign Root CA - G1 [...] dated after November 16, 2026 11:59:59 PM UTC", and "landed a CRLSet update blocking the Subject Public Key Info (SPKI) hashes of the affected intermediate CAs". Same quote-the-source style as the existing entries.
- A private `entry(name, orgs, cns, after, source)` constructor (`distrust.rs:entry`) keeps the built-in table as readable as the old static.
- The matcher lives in a private `covers(ca, cert, leaf_not_before)` (`distrust.rs:covers`), so `distrust_of` stays find-and-log. A filled list whose issuer field is `None` never matches; an empty list is no constraint.
- `O=` containment keeps its old semantics: cert side trimmed, both sides ASCII-lowercased. `CN=` equality trims both the listed value and the cert's value and compares ASCII case-insensitively (`distrust.rs:covers`).
- `validate()` errors name the entry and the offending key in its YAML spelling (`organizations`, `issuer-common-names`), so Phase 2 only prefixes the path and index (`distrust.rs:validate`).
- `test_calculate_stats` switched to `AppState::new` instead of growing the struct literal, so the next `AppState` field does not touch it; its now-unused `DashMap` import is gone (`src/tui/target.rs:tests`).
- The debug log line logs the issuer `O=` and `CN=` as `{:?}`, since both are `Option`s at that seam (`distrust.rs:distrust_of`).
- `serde` with `derive` was already a dependency, so `DistrustedCa` derives `Deserialize` with no `cargo add`. Nothing deserializes it until Phase 2.

### Deviations
- None. Signatures match the doc's API Design exactly.

### Tradeoffs
- `builtin_distrusted_cas()` builds a fresh `Vec` vs a `LazyLock` static: the doc specifies a function, it runs once per `AppState::new`, and owned entries let user entries share the same `Vec`.
- Date bite check broke `>` -> `>=` (an off-by-one) vs "always true": the subtler regression, and it still fails the G1 test.

### Bite checks (2026-11-07; each break reverted, file confirmed byte-identical with `cmp`)
- CN comparison forced true (`.any(|_listed| true)`): `cargo test --lib distrust` -> 3 failed: `an_emudhra_issuer_with_an_unlisted_cn_matches_nothing`, `issuer_cn_matching_trims_ignores_ascii_case_and_never_uses_containment`, `emsign_g1_is_distrusted_only_after_2026_11_16`.
- Date comparison `date_naive() > after` -> `>=`: 3 failed: `emsign_g1_is_distrusted_only_after_2026_11_16`, `entrust_is_covered_only_for_leaves_issued_after_its_date`, `every_spelling_the_sources_name_is_matched_by_containment`.
- Extra: the old `issuer_organization?` early return re-created (an empty `organizations` still demands an `O=`): 1 failed: `a_cn_only_entry_matches_a_cert_with_no_organization`.
- Restored: `cargo test --lib distrust` -> 18 passed; `cargo test --lib emsign` -> 3 passed (acceptance criterion 1); `cargo test --lib purdue` -> 1 passed; `otto ci` green (901 passed, 1 ignored).

### Open questions
- None.

## Phase 2: `scan.yml` overlay

### Design decisions
- `load_from` matches `ErrorKind::NotFound` only for "no file"; every other read error returns `Err` with the path (`src/config.rs:load_from`). A directory at the path reads as an error, not as missing.
- A comment-only or blank file parses as `Option<Config>`, `None` becoming `Config::default()` (`src/config.rs:load_from`).
- Validation failures read `invalid config <path>: distrusted-cas entry <index>: <validate() message naming the entry and key>` via `wrap_err_with` over Phase 1's `validate()` (`src/config.rs:load_from`). `{:#}` prints the chain.
- `xdg_config_dir` is the `rules/rust.md` template, private; `config_path` is public (`src/config.rs`).
- `load()` runs right after `Args::parse()`, before target resolution, and its error propagates out of `run()` (`src/main.rs`); the user entries are appended with `extend` onto the built-ins `AppState::new` filled.
- `cargo add --dev tempfile` for the tests (the `rules/rust.md` env test template and temp config files use it). `serde_yaml` added with `cargo add` (0.9.34+deprecated, as the doc expects).
- `the_shipped_example_entry_is_valid_once_uncommented` locates the example block with `"\n# distrusted-cas:\n"`, not the bare key, because the prose line `# distrusted-cas: entries ADDED ...` earlier in the file would match first.
- Extra tests beyond the list: blank file, unknown top-level key, entry missing `name`.

### Deviations
- None. One observation: for AC2's `Broken` entry (only `name`), serde fails first on the missing required `source` field, so the error reads `distrusted-cas[0]: missing field source` and does not name the entry. The path is named, which is what AC2 requires. `validate()`'s entry-name message is reached only for entries that parse (the no-matcher test supplies `source`).

### Tradeoffs
- `tempfile` as a dev-dependency vs hand-rolled temp dirs: the `rules/rust.md` test template uses it, and cleanup is automatic.

### Acceptance criteria observed (2026-11-07, `cargo build`, `BIN=target/debug/scan`, scratch dir with the doc's exact YAML)
- AC2: `XDG_CONFIG_HOME=$D/bad timeout 8 $BIN --no-tui example.com` -> `AC2 exit=1`. stderr:
  ```
  Error: invalid config <D>/bad/scan/scan.yml

  Caused by:
      distrusted-cas[0]: missing field `source` at line 2 column 5
  ```
- AC3: `bin/snap.py google.com --bin "env XDG_CONFIG_HOME=$D/gts $BIN" --cols 200 --rows 56 --wait 10 --ansi ...`: CA row reads `CA: Google Trust Services (WE2) (distrusted CA)`; chain rows `*.google.com (distrusted CA)` and `WE2 (distrusted CA)`. Control with `$D/empty`: 0 lines match `distrusted`.
- AC4: `bin/snap.py www.purdue.edu --bin "env XDG_CONFIG_HOME=$D/empty $BIN" ...`: `emSign Root TLS CA - G1` on 1 line, 0 lines match `distrusted`, CA row `CA: Internet2 (InCommon Intermediate CA - OVG2C)`. Leaf `notBefore=Nov  2 21:03:10 2026 GMT`, on or before the cutoff, so no mark is correct (date-bound note holds).
- `cargo test --lib config`: 16 passed. `otto ci`: green.

### Open questions
- None.
