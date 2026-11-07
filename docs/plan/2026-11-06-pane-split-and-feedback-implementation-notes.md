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
