# Testing & Test Suite: pqblocks-tls-interop

This document details the test structure, coverage metrics, and verification instructions for `pqblocks-tls-interop`.

---

## Test Organization

The test suite comprises 17 test modules covering 235 automated tests:

| Module | Purpose | Count |
|---|---|---|
| `tests/ci/test_downgrade_detection.py` | Detects classical-only fallback and non-hybrid group servers | 15 |
| `tests/ci/test_hybrid_group_probe.py` | Validates ServerHello parsing and extension identification | 11 |
| `tests/ci/test_sni_transport.py` | SNI parameter handling, custom ports, and socket timeouts | 16 |
| `tests/test_hybrid_probe.py` | Core probe logic and result object assertions | 19 |
| `tests/test_integration_probe.py` | Comprehensive network simulation and mock TLS exchanges | 43 |
| `tests/test_integration_probe_actual.py` | End-to-end integration and codepoint checks | 20 |
| `tests/test_line_335_cover.py` | Coverage verification for CLI entrypoints | 1 |
| `tests/test_missing_lines.py` | Subprocess execution, CLI flag parsing (`--layout`, `-p`, `--sni`) | 8 |
| `tests/test_official_vectors.py` | NIST ACVP test vector integration | 1 |
| `tests/test_probe_coverage.py` | Branch and error condition coverage | 29 |
| `tests/test_probe_integration.py` | Extended server interaction simulations | 37 |
| `tests/test_probe_lines.py` | Code branch coverage for error reporting | 18 |
| `tests/test_remaining_coverage.py` | Edge cases in socket handling | 10 |
| `tests/test_report_documentation.py` | Specification constants assertion | 1 |
| `tests/test_runpy_main_guard.py` | Script execution via `runpy` module | 1 |
| `tests/test_script_execution.py` | CLI execution via `python -m` | 1 |
| `tests/test_tls_hybrid.py` | Key derivation and layout validation | 4 |

**Total Tests**: 235 passing.

---

## Code Coverage

Measured across CPython 3.14:

| Module | Statements | Missing | Coverage |
|---|---|---|---|
| `src/pqblocks_tls_interop/__init__.py` | 2 | 0 | 100% |
| `src/pqblocks_tls_interop/interop.py` | 15 | 1 | 93% |
| `src/pqblocks_tls_interop/verifier/__init__.py` | 0 | 0 | 100% |
| `src/pqblocks_tls_interop/verifier/probe.py` | 190 | 0 | 100% |
| **TOTAL** | **207** | **1** | **99%** |

---

## Running Tests

### Standard Test Execution

```bash
pytest tests/
```

### With Code Coverage

```bash
pytest --cov=pqblocks_tls_interop --cov-report=term-missing tests/
```
