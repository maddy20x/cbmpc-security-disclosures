# 🔒 CB-MPC Security Vulnerability Disclosures

**Security Research Findings | Responsible Disclosure**

## Overview

This repository contains security vulnerability disclosures for the Coinbase CB-MPC cryptographic library. All findings have been validated with working proof-of-concept code and are being disclosed responsibly through the Coinbase Bug Bounty Program.

## Vulnerabilities Discovered

### 1. 🔴 Critical: Negative Size in buf_t::resize() and alloc()
- **File**: `src/cbmpc/core/buf.cpp`
- **Lines**: 145-203
- **Type**: Out-of-Bounds Memory Access
- **Severity**: HIGH (CVSS 7.5)
- **Status**: ✅ Confirmed with PoC
- **Impact**: Heap corruption, DoS, potential RCE

### 2. 🟡 Medium: Uninitialized Memory in buf_t
- **File**: `src/cbmpc/core/buf.cpp`
- **Function**: `buf_t::buf_t(int)`
- **Type**: Information Disclosure
- **Severity**: MEDIUM (CVSS 5.3)
- **Status**: ✅ Confirmed with PoC
- **Impact**: Heap data leak

### 3. 🟡 Medium: Uninitialized Memory in bits_t
- **File**: `src/cbmpc/core/buf.cpp`
- **Function**: `bits_t::alloc()`
- **Type**: Information Disclosure
- **Severity**: MEDIUM (CVSS 5.3)
- **Status**: ✅ Confirmed with PoC
- **Impact**: Heap data leak

## PoC Results Summary

| Vulnerability | Test | Result |
|---------------|------|--------|
| Negative Size | resize(-1) | ✅ size = -1 |
| Negative Size | alloc(-100) | ✅ size = -100 |
| Negative Size | resize(-2000) | ✅ CRASH (confirmed) |
| Uninitialized buf_t | Multiple allocations | ✅ 100% leak rate |
| Uninitialized bits_t | Multiple allocations | ✅ 100% leak rate |

## Quick Test

```bash
# Clone the repository
git clone https://github.com/maddy20x/cbmpc-security-disclosures
cd cbmpc-security-disclosures

# Build and test all vulnerabilities
chmod +x build.sh
./build.sh

# Or test individually
g++ -std=c++17 -O0 -o poc_neg poc_negative_size.cpp && ./poc_neg
g++ -std=c++17 -O0 -o poc_uninit_buf poc_uninitialized_buf.cpp && ./poc_uninit_buf
g++ -std=c++17 -O0 -o poc_uninit_bits poc_uninitialized_bits.cpp && ./poc_uninit_bits
