# Security Policy

## Supported Versions

This repository contains security vulnerability disclosures for the Coinbase CB-MPC library.

| Version | Affected | Status |
|---------|----------|--------|
| All versions using affected functions | ✅ | Vulnerable |

## Reporting a Vulnerability

### Current Disclosures

| Vulnerability | Severity | Status |
|---------------|----------|--------|
| Negative Size in `buf_t::resize()`/`alloc()` | HIGH | ✅ Confirmed |
| Uninitialized Memory in `buf_t` | MEDIUM | ✅ Confirmed |
| Uninitialized Memory in `bits_t` | MEDIUM | ✅ Confirmed |

### Responsible Disclosure

These vulnerabilities have been disclosed responsibly through the Coinbase Bug Bounty Program.

**Contact**: [Coinbase Bug Bounty Program](https://www.coinbase.com/legal/bug-bounty)

### Disclosure Process

1. **Discovery**: July 6, 2026
2. **Validation**: July 7, 2026
3. **Responsible Disclosure**: July 7, 2026

## Acknowledgments

These findings were discovered and validated by independent security researchers.

## Policy

- Do not exploit vulnerabilities in production systems
- Follow responsible disclosure practices
- Use findings only for authorized security research

---

*For more details, see [vulnerability_report.md](vulnerability_report.md)*
