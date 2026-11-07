# Design Document: Distrust config overlay, issuer-CN matching, eMudhra

**Author:** Scott Idler
**Date:** 2026-11-07
**Status:** Draft
**Review Passes Completed:** 5/5 (see Pass Log)
**Review Panel:** round 1 folded in (see Review Panel Round 1)

## Summary

scan marks a CA `(distrusted CA)` from a static table that matches only the issuer `O=`. Chrome's eMudhra action (October/November 2026) cannot be written in that table: it fully distrusts one eMudhra root and date-limits another, and both carry the same `O=`. This plan:

- adds issuer `CN=` matching to the table
- adds the two eMudhra entries
- lets a user add entries in `~/.config/scan/scan.yml`, so a new browser action does not need a scan release

## Problem Statement

### Background

- `src/scan/tls/distrust.rs` holds `DISTRUSTED_CAS`, a `&'static [DistrustedCa]`. Each entry has `organizations`, an optional `distrusted_after` date and a `source` URL.
- `distrust_of(issuer_organization, leaf_not_before)` returns the first entry where:
  - the cert's issuer `O=` contains one of the entry's organizations (ASCII case-insensitive)
  - and, if the entry is dated, the leaf's `notBefore` day is after `distrusted_after`
- `src/tui/cert.rs` `ca_line` and `chain_lines` call it once per presented certificate, then mark the CA row and the matching chain rows `BAD`.
- The previous plan made the table static on purpose (`docs/plan/2026-11-06-pane-split-and-feedback.md`, Non-Goals and Resolved Decisions): "If it needs to change faster than releases, move it to config then."
- The TC TrustCenter entry (`ef3a3dd`) is committed on `main` but not released.

### Problem

1. **eMudhra cannot be expressed.** Google's post (Oct 20, 2026, updated Nov 4, 2026):
   - **emSign ECC Root CA - G3:** removed from the Chrome Root Store, which covers every certificate under it. Rollout began Oct 27, 2026.
   - **emSign Root CA - G1:** for Chrome 153+, TLS certificates whose earliest SCT (Signed Certificate Timestamp, the date a cert was logged) falls after Nov 16, 2026 11:59:59 PM UTC are no longer trusted.
   - **The compromised intermediates themselves:** Chrome blocked them by SPKI (Subject Public Key Info, the public key) through CRLSet, its revocation-push channel. That covers every path to them. There are six TLS intermediates: `EM {DV,OV,EV} TLS CA - G3B` (`O=eMudhra BV`) and `- G3C` (`O=eMudhra Inc`). Sectigo's `AAA Certificate Services` also cross-signs each one. A chain through that cross-sign never names an emSign root (see Phase 0).
   - Both roots are `O = eMudhra Technologies Limited` (see Phase 0). An `O=`-only entry has two bad choices:
     - Undated, it flags pre-cutoff G1 certs, which Chrome still trusts. www.purdue.edu serves one today.
     - Dated, it misses pre-cutoff G3 certs.
2. **New actions wait for a release.** The table can only grow through a code change, a release and a reinstall. Scott (2026-11-07): "it might be good to encode some of these into the binary but also provide a way via config file for the user to add more in a config so that they binary doesnt have to be rebuilt to add a new entry to the distrust".

### Goals

- G1 (Scott): built-in entries stay in the binary.
- G2 (Scott): a user adds entries in `~/.config/scan/scan.yml` (or `$XDG_CONFIG_HOME/scan/scan.yml`) with no rebuild.
- G3 (Scott, "what about the recent emudra"): scan models Chrome's eMudhra action:
  - G3 root: undated
  - G1 root: dated 2026-11-16
  - the six compromised TLS intermediates, by whichever root signed them: undated
- G4 (follows from G3): an entry can match on the issuer `CN=` as well as the `O=`.
- G5 (taste, fail closed): a config file that cannot be read, parsed or validated stops scan with an error naming the file. A bad file is never treated as an empty list.

### Non-Goals

- **Removing or overriding a built-in from config.** Parked. Revisit if a built-in entry flags a cert that a browser trusts.
- **A `--config <path>` flag.** Parked. The XDG path plus `$XDG_CONFIG_HOME` covers the ask. Revisit when scan grows a second config key.
- **Fetching distrust data at runtime** (CCADB, CRLSet). Excluded. scan stays offline for this, and the source of truth stays in a reviewed table or the user's own file.
- **Key-based matching** (SPKI hash, or Authority Key Identifier). Parked; see Alternatives. Revisit if a CN collision causes a false positive.
- **eMudhra's other roots** (C1, ECC C3). CCADB lists their Chrome status as `Removed`, but no Chrome post gives a date or scope. Excluded until a source exists. Google says it is still reviewing eMudhra's remaining roots.
- **A browser verdict.** Unchanged from the previous plan: this is a heuristic on what scan can see. scan does not verify paths or parse SCTs.
- **Showing `(distrusted CA)` in `--no-tui` / `--debug` output.** Excluded; this predates this plan. `src/pretty.rs` never calls `distrust_of`. A user entry is still loaded and validated in those modes, and the README says the mark is shown only in the TUI.
- **Listing the G1 issuing CAs (`emSign SSL CA - G1`, `emSign EV SSL CA - G1`) so a leaf-only chain is flagged.** Parked. It is the leaf-only limit that every entry accepts. The fix is also incomplete: the InCommon issuers are `O=Internet2`, so they cannot join an entry that needs `O=eMudhra Technologies Limited`.
- **An exhaustive audit of every eMudhra path** (sorted into covered, excluded and cross-signed). Parked. Phase 0 covers the paths that the cited action names.

## Proposed Solution

### Overview

- `DistrustedCa` becomes an owned, `serde`-deserializable struct, with a new `issuer-common-names` list.
- An entry matches a certificate when every list the entry fills matches, plus the date rule:
  - `organizations` (if not empty): the issuer `O=` contains one of them. This is the current rule.
  - `issuer-common-names` (if not empty): the issuer `CN=` equals one of them. The match trims whitespace and is ASCII case-insensitive.
  - `distrusted-after` (if set): the leaf `notBefore` day is after it. This is the current rule.
  - A cert with no issuer `O=` never matches an entry that has `organizations`. A cert with no issuer `CN=` never matches an entry that has `issuer-common-names`.
- Every existing built-in leaves `issuer-common-names` empty, so their behavior is unchanged. The ported tests prove it.
- The loaded list is the built-ins followed by the user's entries. It lives on `AppState`, and the cert pane reads it from there.
- `src/config.rs` loads `scan.yml` once at startup, after argument parsing and before target resolution.

### Architecture

**Why matching the issuer CN works for eMudhra.** The hierarchies are three levels deep. A leaf's issuer is the issuing CA, never the root. The root's name shows up as the issuer of a presented intermediate.

From the CCADB records and the live chain in Phase 0:

```
emSign Root CA - G1  (root, O=eMudhra Technologies Limited)
├── emSign SSL CA - G1 / emSign EV SSL CA - G1          (issue leaves directly)
└── emSign Root TLS CA - G1   (an intermediate here; also a separate, untrusted root)
    ├── EM DV|OV|EV TLS CA - G2A-1/G2B/G2C, emSign TLS CA - G1
    └── InCommon Intermediate CA - DVG2C/OVG2C/EVG2C, InCommon RSA IGTF Server CA 4   (O=Internet2)
```

The G3 (ECC) tree has the same shape: `emSign ECC Root CA - G3` -> `emSign Root TLS CA - G3` -> issuing CAs.

- Each eMudhra entry lists two names: the root's CN and its `Root TLS CA` CN.
  - The second name catches chains where the server stops below the root-signed `emSign Root TLS CA` cert.
  - It also catches the InCommon intermediates. Their own issuer is `O=eMudhra Technologies Limited, CN=emSign Root TLS CA - G1`, so `O=` and CN both match even though the leaf's issuer is `O=Internet2`.
- `organizations: ["eMudhra Technologies Limited"]` stays on both entries. Both lists must match, so a CN reused by another CA owner does not trigger the entry.
- **The compromised intermediates need their own entry.** Each one has two parents: an emSign `Root TLS CA - G3` and Sectigo's `AAA Certificate Services` (`O=Comodo CA Limited`). The cross-signed path never names an emSign root, so the G3 entry cannot catch it. The third entry matches on the intermediates' own CNs, under `O=eMudhra BV` and `O=eMudhra Inc`. It needs no date, because Chrome blocked the keys.
  - This entry matches the leaf's issuer, so it fires even when the server sends only the leaf.
- **The heuristic's limit:** if a server sends only the leaf, scan sees just the issuing CA's name and cannot tell which root is above it. That case reads as not distrusted. The previous plan accepted the same limit for the existing entries.

**Config load** (`src/config.rs`, new):

- `xdg_config_dir()` follows the `rules/rust.md` helper: `$XDG_CONFIG_HOME` if it is absolute, else `$HOME/.config`. It never uses `dirs::config_dir()`.
- `config_path()` returns `xdg_config_dir()/scan/scan.yml`. If there is no home directory and no absolute `$XDG_CONFIG_HOME`, it returns `None`. `load()` then uses the built-ins only and logs a `warn`.
- `load_from(path) -> Result<Config>`:
  - **Missing file:** `fs::read_to_string` returns `io::ErrorKind::NotFound`. Return `Config::default()`, which holds no user entries, and log it at `info`. Only `NotFound` counts as missing. Do not copy bump's `!path.exists()`: it also reports false when the path cannot be read, which would turn a permission error into "no file".
  - **Comment-only or blank file:** deserialize as `Option<Config>`; `None` becomes `Config::default()`. A copied example file is all comments, so it must load.
  - **Read error:** `Err`, with the path in the message.
  - **YAML error or unknown key:** `Err`, with the path and serde's message (`deny_unknown_fields` names the bad key).
  - **Validation error:** `Err`, naming the path, the entry index and the entry name.
  - **Success:** log at `info` the path and how many user entries loaded.
- `load() -> Result<Config>` calls `load_from` on `config_path()`. If the path is `None`, it returns `Config::default()`.
- `main.rs` `run()` calls `scan::config::load()` right after `Args::parse()`. On `Err`, it returns the error, so scan exits non-zero before resolving the target or starting the TUI. Debug and `--no-tui` modes load the file the same way, so a bad file fails the same way in every mode.

**Validation** (`distrust::validate(&DistrustedCa) -> Result<()>`). One function checks built-ins and user entries, so the two cannot drift:

- `name` is not empty after trimming
- at least one of `organizations` and `issuer-common-names` is not empty
- no string in either list is empty after trimming
- `source` starts with `https://`

**Wiring into the TUI:**

- `AppState` gains `pub distrusted_cas: Vec<DistrustedCa>`. `AppState::new` fills it with `builtin_distrusted_cas()`, so existing tests and callers keep today's behavior.
- `main.rs` appends the user entries: `app_state.distrusted_cas.extend(config.distrusted_cas)`. `AppState::new` has already filled in the built-ins.
- `cert.rs` `ca_line` and `chain_lines` take the list (`&state.distrusted_cas`) and pass it to `distrust_of`.

### Data Model

```rust
// src/scan/tls/distrust.rs
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct DistrustedCa {
    pub name: String,
    #[serde(default)]
    pub organizations: Vec<String>,
    #[serde(default)]
    pub issuer_common_names: Vec<String>,
    #[serde(default)]
    pub distrusted_after: Option<NaiveDate>,
    pub source: String,
}

// src/config.rs
#[derive(Debug, Default, Clone, PartialEq, serde::Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub distrusted_cas: Vec<DistrustedCa>,
}
```

- `DISTRUSTED_CAS` (the static) becomes `pub fn builtin_distrusted_cas() -> Vec<DistrustedCa>`. The entries and their source comments carry over unchanged, and three eMudhra entries are added:

| name | organizations | issuer-common-names | distrusted-after | source |
|---|---|---|---|---|
| `eMudhra (emSign ECC Root CA - G3)` | `eMudhra Technologies Limited` | `emSign ECC Root CA - G3`, `emSign Root TLS CA - G3` | none | Google post below |
| `eMudhra (emSign Root CA - G1)` | `eMudhra Technologies Limited` | `emSign Root CA - G1`, `emSign Root TLS CA - G1` | `2026-11-16` | Google post below |
| `eMudhra (compromised intermediates)` | `eMudhra BV`, `eMudhra Inc` | `EM DV TLS CA - G3B`, `EM OV TLS CA - G3B`, `EM EV TLS CA - G3B`, `EM DV TLS CA - G3C`, `EM OV TLS CA - G3C`, `EM EV TLS CA - G3C` | none | Google post below |

Source for all three: https://blog.google/security/protecting-chrome-and-android-users-from-compromised-emudhra-intermediate-ca-certificates/

**Example `scan.yml`** (shipped at the repo root as the one annotated example, all lines commented out):

```yaml
# scan config: copy to ~/.config/scan/scan.yml (or $XDG_CONFIG_HOME/scan/scan.yml).
# distrusted-cas: entries ADDED to scan's built-in list; they never replace it.
# An entry matches a presented certificate when every list it fills matches:
#   organizations: the issuer O= CONTAINS one of these (case-insensitive)
#   issuer-common-names: the issuer CN= EQUALS one of these (case-insensitive)
#   distrusted-after: only leaves whose notBefore day is after this date (omit = every leaf)
# A bad file stops scan with an error naming this file; it is never ignored.
#
# distrusted-cas:
#   - name: Example CA
#     organizations: ["Example CA Ltd."]
#     issuer-common-names: ["Example Root CA - R1"]
#     distrusted-after: 2026-12-31
#     source: https://example.com/announcement
```

### API Design

```rust
// src/scan/tls/distrust.rs
pub fn builtin_distrusted_cas() -> Vec<DistrustedCa>;
pub fn validate(ca: &DistrustedCa) -> eyre::Result<()>;
pub fn distrust_of<'a>(
    cas: &'a [DistrustedCa],
    cert: &CertificateInfo,
    leaf_not_before: DateTime<Utc>,
) -> Option<&'a DistrustedCa>;

// src/config.rs
pub fn config_path() -> Option<PathBuf>;
pub fn load_from(path: &Path) -> eyre::Result<Config>;
pub fn load() -> eyre::Result<Config>;
```

- `distrust_of` takes the whole `CertificateInfo`, so a caller cannot pass the `O=` without the `CN=`.
- The debug log line gains the matched `common_name`.

### Implementation Plan

#### Phase 0: Prove the eMudhra names and the chain shape (done, zero code)

**Model:** sonnet

- Read both roots' subjects from Chrome's root store (`net/data/ssl/chrome_root_store/root_store.certs`, tag 140.0.7339.80).
- List every CCADB certificate whose parent is an emSign root (`AllCertificateRecordsCSVFormatv4`).
- Find a live site that serves an eMudhra chain.
- **Success criteria:** both roots' `O=` values are recorded; the intermediate layer is named; one live chain is captured.

**Result (observed 2026-11-07):**

- Root store:
  - `Subject: C = IN, OU = emSign PKI, O = eMudhra Technologies Limited, CN = emSign Root CA - G1`
  - `Subject: C = IN, OU = emSign PKI, O = eMudhra Technologies Limited, CN = emSign ECC Root CA - G3`
  - Same `O=`, so CN matching is required.
- CCADB Chrome status:
  - `emSign ECC Root CA - G3`: `Blocked`
  - `emSign Root CA - G1`: `Included`
  - `emSign Root TLS CA - G1` under G1: `Trusted`
  - `emSign Root TLS CA - G3` under G3: `Not Trusted`
  - The InCommon intermediates (`DVG2C`, `OVG2C`, `EVG2C`, `RSA IGTF Server CA 4`) sit under `emSign Root TLS CA - G1`.
- `openssl s_client -connect www.purdue.edu:443 -showcerts`:
  ```
  0 s:... CN=www.purdue.edu
    i:C=US, O=Internet2, CN=InCommon Intermediate CA - OVG2C
    v:NotBefore: Nov  2 21:03:10 2026 GMT
  1 s:C=US, O=Internet2, CN=InCommon Intermediate CA - OVG2C
    i:C=IN, O=eMudhra Technologies Limited, CN=emSign Root TLS CA - G1
  2 s:C=IN, O=eMudhra Technologies Limited, CN=emSign Root TLS CA - G1
    i:C=IN, OU=emSign PKI, O=eMudhra Technologies Limited, CN=emSign Root CA - G1
  ```
  - The leaf predates the cutoff, so it must not be flagged.
  - An undated `O=eMudhra` entry would flag it (Problem 1).
- No live G3 chain was found. www.emudhra.com and emsign.com serve Sectigo certs.
- The compromised intermediates (added after review round 1).
  - CCADB lists a second record for each `EM {DV,OV,EV} TLS CA - G2*/G3*` with parent `AAA Certificate Services`, valid from 2025-05-14 or 2025-06-18.
  - A public list of the compromised certs is at https://emudhra.we-have-a-problem.com/impacted-intermediates.json. It is third-party, so it is used only to name the certs; each cert was then decoded with `openssl x509 -subject -issuer`.
  - It holds 16 records: 8 keys, each with an emSign parent and an AAA cross-sign. That matches Google's "eight" keys. 6 are TLS keys, matching the post's "six intermediate CAs"; 2 are code-signing (`EM OV CS CA - G3B/G3C`).
  - The decoded AAA cross-signs:
    ```
    subject=C=NL, O=eMudhra BV, CN=EM DV TLS CA - G3B
    issuer=C=GB, ST=Greater Manchester, L=Salford, O=Comodo CA Limited, CN=AAA Certificate Services
    subject=C=US, O=eMudhra Inc, CN=EM DV TLS CA - G3C
    subject=C=NL, O=eMudhra BV, CN=EM EV TLS CA - G3B
    subject=C=US, O=eMudhra Inc, CN=EM EV TLS CA - G3C
    subject=C=NL, O=eMudhra BV, CN=EM OV TLS CA - G3B
    subject=C=US, O=eMudhra Inc, CN=EM OV TLS CA - G3C
    ```
    Each of the six has the same AAA issuer.
  - All 16 read `revocation.status: revoked`, reason `ca_compromise`, dated 2026-10-18.

#### Phase 1: Issuer-CN matching, owned table, eMudhra entries

**Model:** opus

- `src/scan/tls/distrust.rs`:
  - Change `DistrustedCa` to the owned, `Deserialize` struct in Data Model.
  - Replace the static with `builtin_distrusted_cas()`. Keep every existing entry and its comment. Add the two eMudhra entries with a comment that quotes the post.
  - Add `validate()`.
  - Change `distrust_of` to the new signature and the both-lists-must-match rule.
  - Update the module doc: the list is built in plus the user's config, and it now matches the `CN=` too.
- `src/scan/tls.rs`: re-export `builtin_distrusted_cas` and `validate` in place of `DISTRUSTED_CAS`.
- `src/types.rs`:
  - Add `AppState.distrusted_cas`.
  - Fill it with `builtin_distrusted_cas()` in `new`.
- `src/tui/target.rs` `test_calculate_stats`: it builds `AppState { .. }` as a struct literal, the only one in the tree (`rg -n "AppState \{" src`). Add the new field there, or switch the test to `AppState::new`.
- `src/tui/cert.rs`:
  - Thread `&state.distrusted_cas` into `ca_line` and `chain_lines`.
  - Pass each `cert` to `distrust_of`.
- Tests in `distrust.rs`:
  - Port the existing tests to the new signature (build a `CertificateInfo` in a helper).
  - `emsign_g3_is_distrusted_for_every_leaf`: issuer `O=eMudhra Technologies Limited` with each of the two G3 CNs; leaf dated 2020-01-01. Both match.
  - `emsign_g1_is_distrusted_only_after_2026_11_16`: issuer CN `emSign Root TLS CA - G1`. A leaf on 2026-11-16 23:00 UTC matches nothing. A leaf on 2026-11-17 00:00 UTC matches the G1 entry.
  - `an_emudhra_issuer_with_an_unlisted_cn_matches_nothing`: `O=eMudhra Technologies Limited, CN=emSign Root CA - C1` returns `None`.
  - `a_listed_cn_under_another_organization_matches_nothing`: `O=Other CA, CN=emSign Root CA - G1` returns `None`.
  - `emsign_compromised_intermediates_are_distrusted_as_the_leaf_issuer`: a leaf whose issuer is `O=eMudhra BV, CN=EM DV TLS CA - G3B`, or `O=eMudhra Inc, CN=EM EV TLS CA - G3C`, matches the compromised-intermediates entry at any date. This is the leaf-only and AAA-cross-signed case.
  - `a_cn_only_entry_matches_a_cert_with_no_organization`: an entry with only `issuer-common-names` matches an issuer that has a CN but no `O=`. Today `distrust_of` starts with `issuer_organization?`; this test fails if that early return is ported as-is.
  - `issuer_cn_matching_trims_ignores_ascii_case_and_never_uses_containment`: `" EMSIGN ROOT CA - G1 "` matches. `emSign Root CA - G1 SubCA` does not.
  - `every_builtin_entry_validates`: replaces `every_entry_names_a_source_and_at_least_one_organization`.
  - `validate_rejects_an_entry_with_no_matcher`, plus one case for an empty string and one for a non-`https` source.
- Test in `cert.rs`: `a_purdue_shaped_chain_is_marked_only_after_the_g1_cutoff`. Use the Phase 0 chain:
  - With leaf `notBefore` 2026-11-02, nothing reads `distrusted`.
  - With 2026-11-17, the CA row and the `InCommon Intermediate CA - OVG2C` and `emSign Root TLS CA - G1` chain rows read `(distrusted CA)`.
- Bite check: break the CN comparison (always true) and show the `unlisted_cn` test fails. Break the date comparison and show the G1 test fails.
- **Success criteria:**
  - `cargo test --lib distrust` passes, including every test named above.
  - The Purdue-shaped `cert.rs` test passes.
  - `otto ci` is green.

#### Phase 2: `scan.yml` overlay

**Model:** sonnet

- `cargo add serde_yaml` (the org's YAML crate: `bump`, `rkvr` and `clyde` use it).
- `src/config.rs` (new, declared in `lib.rs`): `Config`, `xdg_config_dir`, `config_path`, `load_from`, `load`, as in Architecture.
- `src/config/tests.rs` (new):
  - `xdg_config_dir_honors_env_and_falls_back` (the `rules/rust.md` template, behind an `ENV_LOCK`)
  - missing file: default
  - comment-only file: default
  - valid entry with unquoted `distrusted-after: 2026-11-16`: loads as that `NaiveDate`
  - unknown key: error names the key and the path
  - entry with no matcher: error names the entry name and the path
  - unreadable path (a directory): error names the path
  - `the_shipped_example_loads_as_default`: the repo-root `scan.yml`, read via `CARGO_MANIFEST_DIR`, loads as `Config::default()`
  - `the_shipped_example_entry_is_valid_once_uncommented`: strip the leading `# ` from the example's `distrusted-cas:` block, then load. The result is one entry that passes `validate()`. This keeps the documented example honest.
- `src/main.rs`:
  - Load the config after `Args::parse()`.
  - On error, return it, so scan exits non-zero.
  - Extend `app_state.distrusted_cas` with the user entries.
- `scan.yml` at the repo root: the annotated example, all lines commented out.
- `README.md`: a short "Config" section.
  - Name the path, the `distrusted-cas` keys and the fail-closed rule.
  - Say that the mark is shown only in the TUI.
  - Point at the repo-root `scan.yml`.
- **Success criteria:**
  - `cargo test --lib config` passes.
  - Acceptance criteria 2 and 3 below hold against the built binary.
  - `otto ci` is green.

## Acceptance Criteria

Shared setup for criteria 2 to 4:
- `cargo build`, then `BIN=$PWD/target/debug/scan`. All three use this one binary, which is also `bin/snap.py`'s default.
- `$D` is a temp dir.
- `$D/empty/` exists with no `scan/scan.yml`.
- `$D/bad/scan/scan.yml` holds exactly:
  ```yaml
  distrusted-cas:
    - name: Broken
  ```
- `$D/gts/scan/scan.yml` holds exactly:
  ```yaml
  distrusted-cas:
    - name: Test GTS
      organizations: ["Google Trust Services"]
      source: https://example.com/test
  ```

- [ ] **1.** `cargo test --lib emsign` runs at least 3 tests, and all pass. One proves G3 is undated, one proves G1 matches only after 2026-11-16, and one proves the compromised intermediates match as the leaf's issuer.
  - Observed on main (`ef3a3dd`): `running 0 tests ... 0 passed; 0 failed; 0 ignored; 0 measured; 891 filtered out`. The tests are added in Phase 1, so the criterion fails today as it should.
- [ ] **2.** `XDG_CONFIG_HOME=$D/bad timeout 8 $BIN --no-tui example.com` exits non-zero and not `124`. Its stderr contains `$D/bad/scan/scan.yml`.
  - Observed on main (`ef3a3dd`, `target/debug/scan`): `AC2 exit=124`. scan ignores the file and keeps scanning.
- [ ] **3.** `bin/snap.py google.com --bin "env XDG_CONFIG_HOME=$D/gts $BIN" --cols 200 --rows 56 --wait 10 --ansi <file>`: the capture's CA row reads `CA: Google Trust Services (WE2) (distrusted CA)`. The control run uses `XDG_CONFIG_HOME=$D/empty`; its capture contains no `distrusted`.
  - Observed on main (`ef3a3dd`, `target/debug/scan`):
    - With `gts`: 0 lines match `distrusted`, and the CA row reads `CA: Google Trust Services (WE2)`.
    - With `empty`: the same.
    - The config is ignored today.
- [ ] **4.** Run `bin/snap.py www.purdue.edu --bin "env XDG_CONFIG_HOME=$D/empty $BIN" --cols 200 --rows 56 --wait 15 --ansi <file>`. The capture contains `emSign Root TLS CA - G1`; this proves the TLS scan finished. It also contains no `distrusted`.
  - Date-bound: this holds only while Purdue's leaf `notBefore` is on or before 2026-11-16. A renewal after that date makes `(distrusted CA)` correct. In that case, check the leaf date and treat a mark as a pass.
  - The `cert.rs` Purdue-shaped test covers the post-cutoff case on any date.
  - Observed on main (`ef3a3dd`, `target/debug/scan`): `emSign Root TLS CA - G1` appears on 1 line, and 0 lines match `distrusted`. The CA row reads `CA: Internet2 (InCommon Intermediate CA - OVG2C)`.
- [ ] **5.** `otto ci` passes on the final commit.
  - Observed on main (`ef3a3dd`): `All CI checks passed!` (run for the TC TrustCenter commit, 2026-11-07).

## Resolved Decisions

- 2026-11-07, Scott: the distrust list moves to built-in plus config overlay. This supersedes the previous plan's "static table in code" decision under that decision's own trigger.
- 2026-11-07, author: user entries are added to the built-ins, never replacing them. Built-ins come first, so a duplicate is harmless and the first match is the one logged. There is no name-collision error: a later release that adds a built-in the user already wrote must not break their scan.
- 2026-11-07, author: `issuer-common-names` matches exactly (trimmed, ASCII case-insensitive), not by containment. Root and intermediate CNs are exact names. With containment, `emSign Root CA - G1` would also match a CN like `emSign Root CA - G1 SubCA`.
- 2026-11-07, author: built-ins and user entries go through the same `validate()`, so the rule for "a valid entry" cannot drift between the two.
- 2026-11-07, author: the list lives on `AppState`, not in a process-global `OnceLock`. The cert pane already reads `&AppState`, tests build their own list, and nothing global needs a set-once guard.

## Alternatives Considered

### Alternative 1: `O=`-only entries for eMudhra
- **Description:** one undated or one dated `O=eMudhra Technologies Limited` entry.
- **Pros:** no matcher change.
- **Cons:** an undated entry flags www.purdue.edu today, but Chrome trusts it. A dated entry misses pre-cutoff G3 certs.
- **Why not chosen:** both choices disagree with the action the entry claims to model.

### Alternative 2: match on the Authority Key Identifier (AKI) or SPKI hash
- **Description:** match an intermediate's AKI against the root's Subject Key Identifier, or hash each presented SPKI as Chrome's CRLSet does.
- **Pros:** exact; no name collisions; matches how Chrome keys its blocks.
- **Cons:**
  - Config entries become hex key IDs that a user cannot read off scan's own output.
  - Needs a new parse of AKI/SPKI in `parse_certificate`.
  - A CN collision under the same `O=` has not been seen.
- **Why not chosen:** CN plus `O=` covers every built-in today and keeps entries readable. Parked in Non-Goals.

### Alternative 3: config replaces the built-in list
- **Description:** if `distrusted-cas` is set, it is the whole list.
- **Pros:** the user can remove a built-in.
- **Cons:** a user with one entry silently loses every built-in, and every later built-in fix.
- **Why not chosen:** Scott asked to add entries, not replace them.

### Alternative 4: process-global list in a `OnceLock`
- **Description:** `main` sets the list once; `distrust_of` reads the global.
- **Pros:** no signature change in `cert.rs`.
- **Cons:** hidden state; tests have to set or race the global.
- **Why not chosen:** `AppState` already reaches every render call.

## Technical Considerations

### Dependencies
- New: `serde_yaml` (added with `cargo add`). The upstream repo is archived, but it is the crate `bump`, `rkvr` and `clyde` use.
- `chrono`'s `serde` feature is already enabled, so `NaiveDate` deserializes from `YYYY-MM-DD`.

### Performance
- One small file read at startup. Matching is a linear scan of about 10 entries for each presented certificate on each render, the same as today.

### Security
- The config file belongs to the user and lives in their XDG directory. It only adds labels, never runs anything, and is never read from the current directory (`rules/rust.md`).
- A user entry can only add a `(distrusted CA)` mark. It cannot hide a built-in one.

### Testing Strategy
- Unit tests in `distrust.rs` cover each list alone, both lists together, the date boundary and validation.
- A `cert.rs` render test runs the Purdue-shaped chain on both sides of the cutoff.
- `config/tests.rs` covers path resolution and every load outcome.
- Bite checks in Phase 1. Acceptance criteria 2 to 4 run against the built binary.

### Rollout Plan
- Ships in the next scan release, together with the unreleased TC TrustCenter commit (`ef3a3dd`).
- Done means live:
  - `command -v scan` and `scan --version` report the new tag.
  - Criteria 2 and 3 pass again with `BIN=$(command -v scan)`.
- Rollback:
  - Delete or move `~/.config/scan/scan.yml` to return to the built-ins only.
  - Or reinstall the previous tag; it ignores the file.
- Blast radius: scan only. No other repo reads this table.
- No migration: with no `scan.yml`, behavior is the built-ins, which gain the two eMudhra entries.

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| A server sends only the leaf, so no root or `Root TLS CA` name appears | Low | Low | The heuristic limit, documented in the module doc; the same limit applies to every existing entry |
| Another CA reuses an emSign CN | Low | Low | `O=` must also match |
| A typo in `scan.yml` stops scan | Med | Low | Intended (G5); the error names the file and the key |
| eMudhra issues new intermediates under a third name | Low | Med | An entry can be added in `scan.yml` without a release; the built-in follows in the next release |
| The comment-only example file fails to parse | Med | Med | An explicit blank/comment-only branch in `load_from`, plus a test |

## Review Panel Round 1

Synthesis: `~/.cache/review-panel/runs/4uhsdNro/synthesis.md`. All 4 questions were answered: CN plus `O=` is sound, fail-closed is right, `AppState` is right, and the criteria were not all runnable as written.

| # | Finding | Disposition |
|---|---|---|
| M1 | The six compromised intermediates are also cross-signed by AAA; neither root entry catches that path | Folded in. Checked against CCADB and decoded certs (Phase 0). A third built-in entry was added, plus a test |
| M2 | AC3's YAML had no `name`, so the file would fail to load | Folded in. The full YAML is in the shared setup. The original observation's file did carry `name: Test GTS`; only the doc text dropped it |
| M3 | `src/tui/target.rs` has an `AppState { .. }` struct literal | Folded in (Phase 1) |
| C1 | No test for a CN-only entry against a cert with no `O=`, nor for trim/case/containment | Folded in (two tests) |
| C2 | Use the default only on `NotFound`; say how a comment-only file is detected | Folded in (`Option<Config>`) |
| C3 | One pinned binary; empty-dir control; AC4 can pass before TLS finishes; AC4 is date-bound | Folded in; all re-run on `main` |
| C4 | Phase 1 test count was wrong | Folded in (count dropped) |
| C5 | Done-means-live check and rollback | Folded in (Rollout Plan) |
| C6 | `main` does not need to rebuild the built-ins | Folded in (`extend`) |
| D1 | List the G1 issuing CAs so a leaf-only chain is flagged (architect) | Parked in Non-Goals, with the reason: the accepted limit, and incomplete for `O=Internet2` |
| D2 | Exhaustive eMudhra path audit | Parked in Non-Goals |
| D3 | "About 10 entries" scale caveat | Dropped as speculative; the statement stays true for the current table |
| D4 | The mark is TUI-only (`pretty.rs`) | Non-Goal; Phase 2's README says so |

## Open Questions

None.

## Pass Log

- **Pass 1 (Draft):** full template from the Phase 0 evidence. The CCADB dump changed the design: the root CN alone is not enough, because the `Root TLS CA` intermediate sits between the root and the issuing CAs. Each entry now lists both CNs.
- **Pass 2 (Correctness):** ran criterion 1 on `main` instead of marking it unrunnable (0 tests, 891 filtered out). Added the no-home-directory case to `config_path` and `load`.
- **Pass 3 (Clarity):** stated that every existing built-in leaves `issuer-common-names` empty, so their behavior is unchanged. Stated how a missing `O=` or `CN=` is handled.
- **Pass 4 (Edge cases):** the shipped example could break silently, because it is all comments and no test reads it. Added two tests: it loads as default, and its entry is valid once uncommented. Right problem? Yes: Scott asked to add entries without a rebuild, and to cover eMudhra.
- **Pass 5 (Excellence):** checked against `rules/rust.md` (XDG helper, `deny_unknown_fields`, no current-directory config) and `bump`'s `config.rs` precedent. No changes.

## References

- Google, "Protecting Chrome and Android Users from Compromised eMudhra Intermediate CA Certificates" (Oct 20, 2026; updated Nov 4, 2026): https://blog.google/security/protecting-chrome-and-android-users-from-compromised-emudhra-intermediate-ca-certificates/
- Chrome Root Store certs: https://chromium.googlesource.com/chromium/src/+/refs/tags/140.0.7339.80/net/data/ssl/chrome_root_store/root_store.certs
- CCADB all-certificates report: https://ccadb.my.salesforce-sites.com/ccadb/AllCertificateRecordsCSVFormatv4
- Previous plan: `docs/plan/2026-11-06-pane-split-and-feedback.md`
- Config precedent: `scottidler/bump` `src/config.rs`
