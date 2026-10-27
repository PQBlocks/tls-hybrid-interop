# Verification Evidence: pqblocks-tls-interop

This document records the empirical verification evidence for `pqblocks-tls-interop` (v0.1.0).

---

## Environment & Build Metadata

- **Package**: `pqblocks-tls-interop`
- **Version**: `0.1.0`
- **Build Backend**: `setuptools>=77`
- **Wheel Artifact**: `pqblocks_tls_interop-0.1.0-py3-none-any.whl`
- **Sdist Artifact**: `pqblocks_tls_interop-0.1.0.tar.gz`
- **Date Verified**: 2026-10-26

---

## Test Execution Summary

Executed in isolated virtual environments across target Python versions:

```
platform linux -- Python 3.14.8, pytest-9.1.1, pluggy-1.6.0
rootdir: <repo>/packages/pqblocks-tls-interop
configfile: pyproject.toml
testpaths: tests
plugins: hypothesis-6.168.0, cov-7.1.0, anyio-4.15.1
collected 235 items

tests/ci/test_downgrade_detection.py ...............                     [  6%]
tests/ci/test_hybrid_group_probe.py ...........                          [ 11%]
tests/ci/test_sni_transport.py ................                          [ 17%]
tests/test_hybrid_probe.py ...................                           [ 25%]
tests/test_integration_probe.py ........................................ [ 42%]
...                                                                      [ 44%]
tests/test_integration_probe_actual.py ....................              [ 52%]
tests/test_line_335_cover.py .                                           [ 53%]
tests/test_missing_lines.py ........                                     [ 56%]
tests/test_official_vectors.py .                                         [ 57%]
tests/test_probe_coverage.py .............................               [ 69%]
tests/test_probe_integration.py .....................................    [ 85%]
tests/test_probe_lines.py ..................                             [ 92%]
tests/test_remaining_coverage.py ..........                              [ 97%]
tests/test_report_documentation.py .                                     [ 97%]
tests/test_runpy_main_guard.py .                                         [ 97%]
tests/test_script_execution.py .                                         [ 98%]
tests/test_tls_hybrid.py ....                                            [100%]

======================== 235 passed, 1 warning in 0.52s ========================
```

- **Python 3.11**: 235 passed in 0.53s
- **Python 3.12**: 235 passed in 0.51s
- **Python 3.13**: 235 passed in 0.52s
- **Python 3.14**: 235 passed in 0.52s

---

## Package Integrity & Security Audit

- **`twine check --strict`**: PASSED (description and metadata valid).
- **Leak Gate Audit**: 35 files scanned, 0 hits (zero internal tokens, rules, or environment leaks).
- **Dependencies**: 0 third-party runtime dependencies.
