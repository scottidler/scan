# TLS Pane

## Overview
The TLS pane provides SSL/TLS certificate and connection analysis, including certificate details, chain of trust, supported protocol versions, and cipher suite information. Features a live expiry countdown (in days) and zoomed/full-detail views for advanced users.

## Display Elements

### Live Updates (Continuous Refresh)
- **Certificate Expiry Countdown**: Days remaining until expiry (updates daily)
- **Connection Status**: TLS handshake success/failure (updates on each HTTP check)

### Static Elements (Fire-once, F5 to refresh)
- **Subject Information**: Common Name (CN), Organization, etc.
- **Issuer Information**: Certificate Authority (CA) details
- **Validity Dates**: Not Before, Not After (issued, expires)
- **Subject Alternative Names (SANs)**: All domains covered by the certificate
- **Certificate Chain Summary**: Show leaf, intermediate, and root CA (summary in dashboard, full chain in zoomed view)
- **Maintainer Info**: Indicate which CA maintains each chain level
- **Supported TLS Versions**: 1.0, 1.1, 1.2, 1.3 (test all)
- **Cipher Suites**: Indicate current cipher, mention supported ciphers
- **Certificate Transparency Logs**: List SCTs if available
- **OCSP Stapling Status**: Indicate if OCSP stapling is enabled
- **Multiple Certificates**: Show all (e.g., RSA and ECDSA)

## Display Strategy

### Summary View (Dashboard)
- **Leaf certificate**: Subject, expiry (days), current cipher, current TLS version
- **Chain summary**: "Chain: Leaf → Intermediate (Let's Encrypt) → Root (ISRG Root X1)"
- **Supported versions/ciphers**: List supported versions, mention ciphers
- **OCSP/CT**: Show status icons
- **Multiple certs**: Indicate if more than one cert is in use ("RSA/ECDSA")

### Zoomed/Expanded View
- **Full certificate chain**: All details for each cert in chain
- **All SANs**: Full list
- **All supported ciphers**: List all
- **Certificate transparency log entries**: Full SCT list
- **Raw PEM (optional)**: For advanced users

## Data Collection Methods

### Certificate Retrieval
```bash
openssl s_client -connect example.com:443 -showcerts
```

### Supported Versions/Ciphers
```bash
# Test each version
openssl s_client -connect example.com:443 -tls1_2
openssl s_client -connect example.com:443 -tls1_3
# List ciphers
openssl ciphers -v
```

### OCSP Stapling
```bash
openssl s_client -connect example.com:443 -status
```

### Certificate Transparency
- Parse SCTs from handshake extensions

## Implementation Notes

### Data Structures
```rust
struct TlsData {
    certificates: Vec<CertificateInfo>,
    chain_summary: Vec<ChainLevel>,
    supported_versions: Vec<TlsVersion>,
    current_version: Option<TlsVersion>,
    current_cipher: Option<String>,
    supported_ciphers: Vec<String>,
    ocsp_stapling: Option<bool>,
    ct_logs: Vec<SctEntry>,
    connection_status: TlsStatus,
    expiry_days: Option<u32>,
}

struct CertificateInfo {
    subject: String,
    issuer: String,
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
    sans: Vec<String>,
    pem: Option<String>,
    cert_type: CertType, // RSA, ECDSA, etc.
}

struct ChainLevel {
    name: String,
    maintainer: String,
    cert_type: CertType,
}

enum TlsVersion {
    Tls10,
    Tls11,
    Tls12,
    Tls13,
}

enum TlsStatus {
    Success,
    Failure(String),
}

struct SctEntry {
    log_id: String,
    timestamp: DateTime<Utc>,
    url: Option<String>,
}

enum CertType {
    Rsa,
    Ecdsa,
    Other(String),
}
```

### Expiry Countdown Logic
- Calculate days remaining from `not_after` date
- Update once per day (no need for sub-day precision)

### Update Frequencies
- **Connection status**: On each HTTP check (every 5s)
- **Expiry countdown**: Daily
- **Full details**: On F5 refresh or zoom

## Error Handling
- **Handshake failure**: Show error in status
- **Untrusted CA**: Indicate in summary
- **Expired certificate**: Highlight in red
- **Multiple certs**: Show all, indicate which is in use

## UI Layout Suggestions

### Summary View
```
┌─ TLS ────────────────────────────────────────┐
│ TLS 1.3   🔒 AES_256_GCM_SHA384             │
│ Expires: 89 days (2025-06-12)               │
│ Subject: CN=example.com                     │
│ Chain: Leaf → Let's Encrypt → ISRG Root X1  │
│ OCSP: ✓   CT: ✓   Certs: RSA/ECDSA         │
│ Supported: 1.2 ✓ 1.3 ✓  Ciphers: ...       │
└─────────────────────────────────────────────┘
```

### Zoomed View
```
┌─ TLS (Expanded) ─────────────────────────────┐
│ Certificate Chain:                           │
│ 1. Leaf: CN=example.com (RSA)                │
│ 2. Intermediate: Let's Encrypt (RSA)         │
│ 3. Root: ISRG Root X1 (RSA)                  │
│ Maintainers: Let's Encrypt, ISRG             │
│                                              │
│ SANs: example.com, www.example.com, ...      │
│ Valid: 2024-03-15 to 2025-06-12              │
│ Supported TLS: 1.0 ✗ 1.1 ✗ 1.2 ✓ 1.3 ✓      │
│ Supported ciphers: ... (full list)           │
│ OCSP Stapling: ✓   CT Logs: 2 entries        │
│                                              │
│ [Raw PEM available]                          │
└─────────────────────────────────────────────┘
```

## Testing Considerations
- Test with single and multi-cert sites (RSA/ECDSA)
- Test with expired, soon-to-expire, and valid certs
- Test with untrusted CAs
- Test with and without OCSP/CT
- Test with all TLS versions and ciphers
- Test zoomed/full chain view
- Test error handling for handshake failures

## Future Enhancements
- **Certificate revocation checks**: CRL/OCSP
- **Key length/algorithm warnings**: Weak keys
- **Automated renewal reminders**
- **Certificate pinning detection**
- **Advanced cipher analysis** 