# Mail Pane

## Overview
The mail pane provides an overview of email security and deliverability DNS records for the target domain. It covers SPF, DKIM, DMARC, and MX records, with provider detection and a deliverability score. The summary view shows primary/default records, while the zoomed view displays all details.

## Display Elements

### Static (F5 to refresh)
- **SPF Record**: TXT (v=spf1), summary and validity
- **DKIM Record(s)**: TXT (default selector in summary, all selectors in zoomed view), validity
- **DMARC Record**: TXT (_dmarc), policy summary and validity
- **MX Records**: Primary mail server in summary, all in zoomed view (with priority)
- **Mail Provider Detection**: Google, Microsoft, custom, etc.
- **Policy Summaries**: SPF (e.g., "~all", "-all"), DMARC (e.g., "p=reject")
- **DKIM Selectors**: Default in summary, all found in zoomed view
- **Record Validity**: Basic syntax check ("valid", "malformed")
- **Deliverability Score**: Aggregate based on presence/quality of records

### Summary View
- **SPF**: Present/absent, summary (e.g., "SPF: present, -all")
- **DKIM**: Present/absent (default selector)
- **DMARC**: Present/absent, policy (e.g., "DMARC: p=reject")
- **MX**: Primary mail server (hostname, provider)
- **Deliverability Score**: e.g., "80% 🟢"

### Zoomed/Expanded View
- **All MX hosts**: With priority, full list
- **All DKIM selectors**: List selectors, show if valid
- **Full record values**: SPF, DKIM, DMARC
- **Policy details**: Full DMARC policy, SPF mechanisms
- **Record validity**: Syntax check results

## Data Collection Methods

### DNS Queries
```bash
dig example.com TXT
dig _dmarc.example.com TXT
dig default._domainkey.example.com TXT
dig example.com MX
```
- For zoomed view, enumerate additional DKIM selectors if needed

### Provider Detection
- Heuristics based on MX hostnames (e.g., Google, Microsoft, custom)

## Implementation Notes

### Data Structures
```rust
struct MailData {
    spf: Option<MailRecord>,
    dkim: Vec<MailRecord>,
    dmarc: Option<MailRecord>,
    mx_records: Vec<MxRecord>,
    provider: Option<String>,
    deliverability_score: Option<f32>,
}

struct MailRecord {
    record_type: MailRecordType,
    selector: Option<String>,
    value: String,
    summary: String,
    valid: bool,
}

struct MxRecord {
    priority: u16,
    host: String,
    provider: Option<String>,
}

enum MailRecordType {
    Spf,
    Dkim,
    Dmarc,
}
```

### Record Validity
- Basic syntax checks for SPF, DKIM, DMARC
- Mark as "valid" or "malformed"

### Deliverability Score
- +points for each present/valid record
- Higher score for strict policies (e.g., DMARC p=reject, SPF -all)
- Deduct for missing/weak/malformed records

### Update Frequencies
- **All data**: On F5 refresh or new target
- **No live updates**: Mail records are static during session

## Error Handling
- **Record not found**: Mark as absent
- **Malformed record**: Mark as invalid, show warning
- **No MX**: Indicate "No mail servers found"

## UI Layout Suggestions

### Summary View
```
┌─ Mail ───────────────────────────────────────┐
│ SPF: ✓ -all   DKIM: ✓ default   DMARC: ✓ p=reject │
│ MX: aspmx.l.google.com (Google)              │
│ Deliverability: 90% 🟢                       │
└─────────────────────────────────────────────┘
```

### Zoomed View
```
┌─ Mail (Expanded) ────────────────────────────┐
│ SPF: v=spf1 include:_spf.google.com ~all     │
│ DKIM (default): v=DKIM1; k=rsa; p=...        │
│ DKIM (selector2): v=DKIM1; k=rsa; p=...      │
│ DMARC: v=DMARC1; p=reject; rua=mailto:...    │
│ MX:                                          │
│   1 aspmx.l.google.com (Google)              │
│   5 alt1.aspmx.l.google.com (Google)         │
│   10 mail.example.com (Custom)               │
│ Validity: SPF ✓ DKIM ✓ DMARC ✓               │
│ Deliverability: 90% 🟢                       │
└─────────────────────────────────────────────┘
```

## Testing Considerations
- Test with all records present/valid
- Test with missing/invalid records
- Test with multiple DKIM selectors
- Test with multiple MX hosts/providers
- Test summary and expanded views

## Future Enhancements
- **Open relay test**: SMTP relay check
- **SPF/DMARC alignment**: Advanced deliverability analysis
- **BIMI record detection**: Brand Indicators for Message Identification 