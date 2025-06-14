# Whois Pane

## Overview
The whois pane provides domain registration and ownership details, focusing on useful, non-redacted information. The summary view shows key fields (registrar, dates, simple status, age), while the expanded view includes all available details and the raw WHOIS output. DNSSEC and registry ID are omitted from this pane.

## Display Elements

### Static (F5 to refresh)
- **Domain Name**
- **Registrar** (company managing the domain)
- **Registrant/Organization** (if public, else indicate "hidden/obfuscated")
- **Contact Email** (if public)
- **Registration Date** (created)
- **Expiration Date**
- **Last Updated Date**
- **Domain Status**
  - **Summary**: Simple status ("Active", "Locked", "On Hold")
  - **Expanded**: Full list of status codes (e.g., clientTransferProhibited) with explanations
- **Name Servers** (as listed in WHOIS)
- **Domain Age** (calculated from registration date)
- **WHOIS Server** (source of data)
- **Raw WHOIS Output** (expanded view only)

### Display Strategy

#### Summary View (Dashboard)
- **Domain**: example.com
- **Registrar**: Namecheap, GoDaddy, etc.
- **Created**: 2020-01-01
- **Expires**: 2025-01-01
- **Status**: Active/Locked/On Hold
- **Registrant**: Public org or "hidden/obfuscated"
- **Domain Age**: e.g., "4 years"
- **Minimal info**: If all contact info is hidden, indicate "Registrant info hidden/obfuscated"

#### Zoomed/Expanded View
- **All available fields**: Full registrant, contact, and status info
- **Full list of status codes**: With explanations/tooltips
- **Name servers**: As listed in WHOIS
- **WHOIS server**: Source
- **Raw WHOIS output**: For advanced users

## Data Collection Methods

### WHOIS Query
```bash
whois example.com
```

## Implementation Notes

### Data Structures
```rust
struct WhoisData {
    domain: String,
    registrar: Option<String>,
    registrant: Option<String>,
    contact_email: Option<String>,
    created: Option<DateTime<Utc>>,
    expires: Option<DateTime<Utc>>,
    updated: Option<DateTime<Utc>>,
    status_simple: Option<String>, // e.g., "Active", "Locked"
    status_codes: Vec<WhoisStatus>,
    name_servers: Vec<String>,
    domain_age: Option<String>,
    whois_server: Option<String>,
    raw_output: Option<String>,
    info_hidden: bool,
}

struct WhoisStatus {
    code: String,
    description: Option<String>,
}
```

### Status Code Mapping
- Map common status codes to simple status for summary
  - `clientTransferProhibited`, `serverTransferProhibited` → "Locked"
  - `clientHold`, `serverHold` → "On Hold"
  - No restrictions → "Active"
- Show all codes in expanded view with explanations

### Update Frequencies
- **All data**: On F5 refresh or new target
- **No live updates**: WHOIS info is static during session

## Error Handling
- **WHOIS lookup failure**: Show "Unknown" for missing fields
- **All info hidden**: Indicate "Registrant info hidden/obfuscated"

## UI Layout Suggestions

### Summary View
```
┌─ Whois ──────────────────────────────────────┐
│ Domain: example.com                         │
│ Registrar: Namecheap                        │
│ Created: 2020-01-01   Expires: 2025-01-01   │
│ Status: Active                              │
│ Registrant: hidden/obfuscated               │
│ Domain Age: 4 years                         │
└─────────────────────────────────────────────┘
```

### Zoomed View
```
┌─ Whois (Expanded) ───────────────────────────┐
│ Domain: example.com                         │
│ Registrar: Namecheap                        │
│ Registrant: Example Org, John Doe           │
│ Contact Email: admin@example.com            │
│ Created: 2020-01-01   Expires: 2025-01-01   │
│ Updated: 2023-12-01                         │
│ Status Codes:                               │
│   clientTransferProhibited (Locked)         │
│   clientHold (On Hold)                      │
│ Name Servers: ns1.example.com, ...          │
│ WHOIS Server: whois.namecheap.com           │
│                                             │
│ [Raw WHOIS output below]                    │
└─────────────────────────────────────────────┘
```

## Testing Considerations
- Test with public and hidden registrant info
- Test with multiple status codes
- Test with missing/unknown fields
- Test summary and expanded views
- Test with various registrars

## Future Enhancements
- **Registrar abuse contact**: For reporting
- **Domain transfer eligibility**: Based on status
- **Automated renewal reminders** 