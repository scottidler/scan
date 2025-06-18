# IPv4/IPv6 First-Class Support Implementation Plan

## Executive Summary

This document outlines the implementation plan for making IPv4 and IPv6 first-class citizens in the scan application. The goal is to allow users to specify protocol preferences (IPv4, IPv6, or Both) and have all scanners respect these preferences while providing protocol-specific results.

**Key Objectives:**
- Enable protocol selection via user interface (TUI key press)
- Provide detailed protocol-specific results for each scanner
- Support concurrent IPv4/IPv6 scanning when requested
- Maintain backward compatibility during migration
- Improve debugging capabilities for dual-stack environments

## Current State Analysis

### Existing Architecture
The scan application currently uses a generic approach where:
- Targets are resolved to IP addresses without protocol preference
- Scanners operate on "primary IP" or "network target" without protocol awareness
- Results are protocol-agnostic (single result per scanner)
- No user control over protocol selection

### Current Scanner Behavior
| Scanner | IPv4/IPv6 Handling | Current Limitations |
|---------|-------------------|-------------------|
| DNS | Separate A/AAAA queries | No protocol filtering |
| Ping | Uses first resolved IP | Cannot compare IPv4 vs IPv6 latency |
| Port | Scans single IP | Missing dual-stack port analysis |
| HTTP/TLS | Connects to first IP | Cannot test both protocol endpoints |
| Traceroute | Uses first resolved IP | Cannot trace both protocols |
| GeoIP | Uses first resolved IP | Missing geographic comparison |
| Whois | Domain-based | Minimal impact |

## Proposed Solution

### Protocol Enum
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Ipv4,    // IPv4 only
    Ipv6,    // IPv6 only 
    Both,    // Both IPv4 and IPv6 (default)
}
```

### Enhanced Target Methods
Add protocol-aware methods to the Target struct:
- `ips_for_protocol(protocol: Protocol) -> Vec<IpAddr>`
- `primary_ip_for_protocol(protocol: Protocol) -> Option<IpAddr>`
- `network_target_for_protocol(protocol: Protocol) -> Option<String>`
- `supports_protocol(protocol: Protocol) -> bool`

### Scanner Trait Changes
```rust
#[async_trait]
pub trait Scanner {
    async fn scan(&self, target: &Target, protocol: Protocol) -> Result<ScanResult>;
    // ... other methods unchanged
}
```

### Protocol-Aware Result Types

#### Example: PingResult Transformation
**Before:**
```rust
pub struct PingResult {
    pub latency: Duration,
    pub packet_loss: f32,
    pub ttl: Option<u8>,
    pub packets_sent: u32,
    pub packets_received: u32,
}
```

**After:**
```rust
pub struct PingResult {
    pub ipv4: Option<PingData>,
    pub ipv6: Option<PingData>,
    pub requested_protocol: Protocol,
    pub scan_duration: Duration,
}

pub struct PingData {
    pub target_ip: IpAddr,
    pub latency: Duration,
    pub packet_loss: f32,
    pub ttl: Option<u8>,
    pub packets_sent: u32,
    pub packets_received: u32,
    pub protocol_version: IpVersion,
}
```

## Technical Design

### Error Handling Strategy
When protocol doesn't match target capabilities:
1. **Fail explicitly** - Return clear error message
2. **Report in TUI** - Show "IPv4 not available for this target"
3. **Log appropriately** - Debug information for troubleshooting

### Concurrent Scanning
For `Protocol::Both`:
- Scanners perform IPv4 and IPv6 operations concurrently using `tokio::join!`
- Results are collected into protocol-specific fields
- Timeouts apply per protocol, not globally

### Backward Compatibility
**Phase 1: Additive Changes**
- Add new protocol-aware fields alongside existing fields
- Populate both old and new fields during transition
- TUI displays old fields initially

**Phase 2: Migration**  
- Update TUI to use new protocol-aware fields
- Add user controls for protocol selection
- Test thoroughly with dual-stack environments

**Phase 3: Cleanup**
- Remove deprecated fields
- Simplify code paths
- Update documentation

## Implementation Plan

### Phase 1: Core Infrastructure (Week 1-2)
**Priority: Critical**

1. **Target Protocol Support**
   - [ ] Add Protocol enum to `src/target.rs`
   - [ ] Implement protocol-aware Target methods
   - [ ] Add comprehensive unit tests
   - [ ] Update Target documentation

2. **Scanner Trait Updates**
   - [ ] Modify Scanner trait signature
   - [ ] Update default implementation in scanner.rs
   - [ ] Update scanner spawning logic
   - [ ] Add protocol parameter threading

### Phase 2: Scanner Implementations (Week 3-4)
**Priority: High**

3. **DNS Scanner** (Easiest - already protocol-aware)
   - [ ] Modify to respect Protocol parameter
   - [ ] Filter A/AAAA records based on protocol
   - [ ] Add protocol validation
   - [ ] Update tests

4. **Ping Scanner** (Medium complexity)
   - [ ] Implement new PingResult structure
   - [ ] Add PingData structure
   - [ ] Support concurrent IPv4/IPv6 pinging
   - [ ] Handle ping command protocol flags (-4, -6)
   - [ ] Update parsing logic
   - [ ] Comprehensive testing

5. **Port Scanner** (High complexity)
   - [ ] Design protocol-aware PortResult
   - [ ] Support scanning multiple IPs per protocol
   - [ ] Handle concurrent port scans across protocols
   - [ ] Update service detection for dual-stack
   - [ ] Performance optimization for large port lists

### Phase 3: Network Scanners (Week 5-6)
**Priority: High**

6. **HTTP Scanner**
   - [ ] Design dual-protocol HttpResult
   - [ ] Handle URL resolution per protocol
   - [ ] Support concurrent HTTP requests
   - [ ] Compare security headers across protocols
   - [ ] Handle redirect chains per protocol

7. **TLS Scanner**
   - [ ] Design dual-protocol TlsResult
   - [ ] Support concurrent TLS handshakes
   - [ ] Compare certificate chains across protocols
   - [ ] Protocol-specific vulnerability analysis

8. **Traceroute Scanner**
   - [ ] Design dual-protocol TracerouteResult
   - [ ] Handle traceroute protocol flags
   - [ ] Concurrent path tracing
   - [ ] Route comparison analysis

### Phase 4: Supporting Scanners (Week 7)
**Priority: Medium**

9. **GeoIP Scanner**
   - [ ] Handle multiple source IPs
   - [ ] Geographic comparison between protocols
   - [ ] ISP/network difference analysis

10. **Whois Scanner** (Minimal changes)
    - [ ] Verify domain-based operation
    - [ ] Update for consistency

### Phase 5: User Interface (Week 8-9)
**Priority: High**

11. **TUI Updates**
    - [ ] Protocol-aware result display
    - [ ] User controls for protocol selection
    - [ ] Visual indicators for protocol status
    - [ ] Error message improvements
    - [ ] Performance metric comparisons

12. **CLI Interface**
    - [ ] Add protocol selection flags (--ipv4, --ipv6, --both)
    - [ ] Default protocol configuration
    - [ ] Help text updates

### Phase 6: Testing & Documentation (Week 10)
**Priority: High**

13. **Comprehensive Testing**
    - [ ] Unit tests for all protocol scenarios
    - [ ] Integration tests with dual-stack targets
    - [ ] Performance benchmarking
    - [ ] Error handling validation
    - [ ] Edge case testing

14. **Documentation**
    - [ ] Update README with protocol features
    - [ ] API documentation updates
    - [ ] User guide for protocol selection
    - [ ] Troubleshooting guide

## Scanner-Specific Implementation Details

### DNS Scanner
- **Protocol::Ipv4**: Query only A records
- **Protocol::Ipv6**: Query only AAAA records  
- **Protocol::Both**: Query both, populate separate fields
- **Complexity**: Low (already has A/AAAA separation)

### Ping Scanner  
- **Protocol::Ipv4**: `ping -4 <target>`
- **Protocol::Ipv6**: `ping -6 <target>`
- **Protocol::Both**: Concurrent pings, compare latencies
- **Complexity**: Medium (command-line flag handling)

### Port Scanner
- **Protocol::Ipv4**: Scan target.primary_ipv4()
- **Protocol::Ipv6**: Scan target.primary_ipv6()  
- **Protocol::Both**: Scan both IPs, compare open ports
- **Complexity**: High (multiple IPs × multiple ports)

### HTTP/TLS Scanners
- **Protocol::Ipv4**: Connect to IPv4 endpoint
- **Protocol::Ipv6**: Connect to IPv6 endpoint
- **Protocol::Both**: Connect to both, compare results
- **Complexity**: High (URL resolution, certificate handling)

## Risk Assessment

### High Risk Items
1. **Performance Impact**: Dual-stack scanning may double scan times
   - *Mitigation*: Concurrent scanning, user-configurable timeouts
   
2. **Complex Result Structures**: New result types may be confusing
   - *Mitigation*: Clear documentation, backward compatibility period

3. **TUI Complexity**: Displaying dual results may clutter interface
   - *Mitigation*: Thoughtful UI design, progressive disclosure

### Medium Risk Items  
4. **Backward Compatibility**: Breaking changes may affect users
   - *Mitigation*: Phased migration, deprecated field warnings

5. **Testing Coverage**: Dual-stack scenarios are complex to test
   - *Mitigation*: Comprehensive test matrix, CI/CD improvements

### Low Risk Items
6. **Code Complexity**: More code paths to maintain
   - *Mitigation*: Good abstractions, comprehensive documentation

## Success Criteria

### Functional Requirements
- [ ] User can select IPv4, IPv6, or Both via TUI key press
- [ ] All scanners respect protocol selection
- [ ] Protocol-specific results are clearly displayed
- [ ] Error messages are clear when protocol is unavailable
- [ ] Performance is acceptable for dual-stack scanning

### Non-Functional Requirements  
- [ ] No regression in single-protocol performance
- [ ] TUI remains responsive during dual scans
- [ ] Memory usage scales reasonably with dual results
- [ ] Code coverage maintains >80% across new functionality

### User Experience Requirements
- [ ] Protocol switching is intuitive and responsive
- [ ] Results clearly distinguish between IPv4/IPv6 data
- [ ] Error states are informative and actionable
- [ ] Documentation is clear and comprehensive

## Timeline Summary

| Phase | Duration | Key Deliverables |
|-------|----------|------------------|
| 1 | 2 weeks | Protocol enum, Target methods, Scanner trait |
| 2 | 2 weeks | DNS, Ping, Port scanner implementations |
| 3 | 2 weeks | HTTP, TLS, Traceroute implementations |  
| 4 | 1 week | GeoIP, Whois scanner updates |
| 5 | 2 weeks | TUI and CLI interface updates |
| 6 | 1 week | Testing, documentation, cleanup |

**Total Duration**: ~10 weeks

## Conclusion

This implementation plan transforms the scan application from a protocol-agnostic tool to a dual-stack networking diagnostic platform. The phased approach ensures stability while delivering incremental value. The emphasis on concurrent scanning and clear result presentation will significantly improve the user experience for network troubleshooting in modern dual-stack environments.

**Next Steps**: 
1. Review and approve this plan
2. Set up development environment for dual-stack testing
3. Begin Phase 1 implementation
4. Establish regular progress reviews 