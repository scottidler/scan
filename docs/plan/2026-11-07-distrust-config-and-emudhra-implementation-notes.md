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
