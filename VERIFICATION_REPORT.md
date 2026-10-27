# Verification Report: pqblocks-tls-interop (v0.1.0)

**Date**: 2026-10-26  
**Auditor**: PQBlocks Independent Release Pipeline  
**Target**: `pqblocks-tls-interop` (TLS 1.3 Hybrid Key Exchange Endpoint Probe & Downgrade Detector)

---

## 1. Executive Summary

`pqblocks-tls-interop` (v0.1.0) has passed all release verification gates:
- **Build & Packaging**: Clean sdist and wheel built; `twine check --strict` passed.
- **Cross-Version Runtime**: Verified across Python 3.11, 3.12, 3.13, and 3.14.
- **Test Integrity**: 235 of 235 tests passed across all target Python versions.
- **Examples**: Both `quickstart.py` and `02_probe_endpoint.py` executed successfully.
- **Public Hygiene**: Zero leakage of internal tokens, paths, or development artifacts.

---

## 2. Gate Verification Details

| Gate / Check | Target | Result | Evidence |
|---|---|---|---|
| Build Artifacts | `dist/*.whl`, `dist/*.tar.gz` | PASS | Built `pqblocks_tls_interop-0.1.0-py3-none-any.whl` |
| PyPI Metadata | `twine check --strict` | PASS | Strict metadata check PASSED |
| Python 3.11 Test Suite | 235 tests | PASS | 235 passed in 0.53s |
| Python 3.12 Test Suite | 235 tests | PASS | 235 passed in 0.51s |
| Python 3.13 Test Suite | 235 tests | PASS | 235 passed in 0.52s |
| Python 3.14 Test Suite | 235 tests | PASS | 235 passed in 0.52s |
| Python 3.11 Example 1 | `quickstart.py` | PASS | Exit code 0 |
| Python 3.11 Example 2 | `02_probe_endpoint.py` | PASS | Exit code 0 |
| Python 3.12 Example 1 | `quickstart.py` | PASS | Exit code 0 |
| Python 3.12 Example 2 | `02_probe_endpoint.py` | PASS | Exit code 0 |
| Python 3.13 Example 1 | `quickstart.py` | PASS | Exit code 0 |
| Python 3.13 Example 2 | `02_probe_endpoint.py` | PASS | Exit code 0 |
| Python 3.14 Example 1 | `quickstart.py` | PASS | Exit code 0 |
| Python 3.14 Example 2 | `02_probe_endpoint.py` | PASS | Exit code 0 |
| Leak Gate | Package directory, wheel, sdist | PASS | 0 leak hits across 35 files |
| Required Files | Governance, CI, legal, docs | PASS | All 18 standard files present |

---

## 3. Scope & Non-Claims

1. **Probe Only**: Does not establish application-layer TLS sessions or encrypt web traffic. Operates strictly as a pre-flight probe and compliance gate.
2. **Non-FIPS Validation**: Independent open-source implementation. Not CMVP/FIPS 140-3 validated.
3. **No External Network Dependency in Tests**: The automated test suite simulates TLS endpoints via standard loopback sockets and mock payloads, executing deterministically without public internet access.

---

## 4. Release Recommendation

**VERIFIED FOR RELEASE**: Meets all functional, performance, security, and documentation standards.
