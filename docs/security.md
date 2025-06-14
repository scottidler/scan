# Security Pane

## Overview
The security pane provides a summary of the domain's web and email security posture, surfacing key HTTP headers and DNS records that impact security. The dashboard view shows summary indicators, while the zoomed/fullscreen view provides full header/record details.

## Display Elements

### Web Security Headers (from HTTP response)
- **HSTS** (Strict-Transport-Security)
- **CSP** (Content-Security-Policy)
- **X-Frame-Options**
- **X-XSS-Protection**
- **Referrer-Policy**
- **X-Content-Type-Options**
- **CORS** (Access-Control-Allow-Origin, etc.)
- **Redirects to HTTPS** (enforced or not)

### Email Security (from DNS TXT records)
- **SPF** (TXT record, v=spf1)
- **DKIM** (TXT record, _domainkey)
- **DMARC** (TXT record, _dmarc)

### Display Strategy

#### Summary View (Dashboard)
- **✓/✗ indicators** for each header/record (present, missing, or weak)
- **Short summary** for each (e.g., "CSP: present, strict", "SPF: missing", "HSTS: present, 1 year")
- **Security score** (aggregate, based on presence/quality of headers/records)
- **Highlight critical issues** (e.g., missing HSTS, no SPF/DMARC, weak CSP)

#### Zoomed/Expanded View
- **Full header/record values**
- **Detailed analysis** (e.g., breakdown of CSP policy, full SPF/DKIM/DMARC strings)
- **Recommendations** for missing/weak policies (optional)

## Data Collection Methods

### HTTP Headers
```bash
curl -I -L --max-redirs 10 https://example.com
```

### DNS TXT Records
```bash
dig example.com TXT
dig _dmarc.example.com TXT
dig default._domainkey.example.com TXT
```

## Implementation Notes

### Data Structures
```rust
struct SecurityData {
    web_headers: Vec<HeaderCheck>,
    email_records: Vec<DnsCheck>,
    https_redirect: Option<bool>,
    security_score: Option<f32>,
}

struct HeaderCheck {
    name: String,
    present: bool,
    summary: String, // e.g., "present, strict", "missing", "weak"
    full_value: Option<String>,
}

struct DnsCheck {
    record_type: EmailRecordType,
    present: bool,
    summary: String, // e.g., "SPF: present, includes _spf.google.com"
    full_value: Option<String>,
}

enum EmailRecordType {
    Spf,
    Dkim,
    Dmarc,
}
```

### Security Score Calculation
- **Headers**: +points for each present, more for strict/secure values
- **Email records**: +points for each present, more for strict/secure policies
- **Critical issues**: Deduct for missing HSTS, no SPF/DMARC, weak CSP, etc.

### Update Frequencies
- **On HTTP/DNS refresh**: When HTTP or DNS data is updated (F5 or live HTTP check)
- **UI refresh**: Every time new data is available

## Error Handling
- **Header not present**: Mark as missing
- **DNS record not found**: Mark as missing
- **Malformed policy**: Mark as weak, show warning in summary

## UI Layout Suggestions

### Summary View
```
┌─ Security ───────────────────────────────────┐
│ HSTS: ✓ 1 year   CSP: ✓ strict   XSS: ✗     │
│ Frame: ✓         Referrer: ✗                │
│ SPF: ✓          DKIM: ✓         DMARC: ✗    │
│ Redirects to HTTPS: ✓                       │
│                                             │
│ Score: 70% 🟡   Critical: HSTS missing      │
└─────────────────────────────────────────────┘
```

### Zoomed View
```
┌─ Security (Expanded) ────────────────────────┐
│ HSTS: max-age=31536000; includeSubDomains    │
│ CSP: default-src 'self'; script-src ...      │
│ X-Frame-Options: DENY                        │
│ X-XSS-Protection: 1; mode=block              │
│ Referrer-Policy: no-referrer                 │
│ X-Content-Type-Options: nosniff              │
│ CORS: Access-Control-Allow-Origin: *         │
│ SPF: v=spf1 include:_spf.google.com ~all     │
│ DKIM: v=DKIM1; k=rsa; p=...                  │
│ DMARC: v=DMARC1; p=quarantine; ...           │
│                                             │
│ [Recommendations for missing/weak policies]  │
└─────────────────────────────────────────────┘
```

## Testing Considerations
- Test with all headers/records present
- Test with missing/weak headers/records
- Test with malformed policies
- Test with domains lacking email security
- Test zoomed/full detail view

## Future Enhancements
- **Cookie analysis**: Secure, HttpOnly, SameSite flags
- **Vulnerability scanning**: Open directories, server version exposure
- **Automated recommendations**: For missing/weak policies 