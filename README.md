# pqblocks-tls-interop

> TLS 1.3 hybrid key exchange (X25519MLKEM768 / RFC 10024) endpoint probe, downgrade detector, and key material validator.

[![CI](https://github.com/PQBlocks/tls-hybrid-interop/actions/workflows/ci.yml/badge.svg)](https://github.com/PQBlocks/tls-hybrid-interop/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

---

## Overview

`pqblocks-tls-interop` is a lightweight, zero-dependency Python library and CLI tool designed to validate post-quantum TLS 1.3 endpoints. It verifies support for the standardized **X25519MLKEM768** hybrid key exchange group per **RFC 10024** and validates key derivation per **RFC 9954**.

The tool operates without completing a full TLS application session: it probes server Hello extensions, detects hybrid group negotiation, alerts on classical downgrades (e.g. classical X25519 only), and validates wire-format key share structures.

### Key Capabilities

- **RFC 10024 Compliance**: Validates hybrid group codepoint `4588` (`0x11EC`) and enforces ML-KEM shared secret first concatenation.
- **Downgrade Detection**: Detects when servers fail to negotiate hybrid groups or downgrade to classical X25519 (codepoint `29`), exiting with distinct return codes for CI/CD gates.
- **Key Material Derivation**: Implements RFC 10024 combined secret derivation and RFC 9954 SHA-384 key material derivation.
- **Zero Third-Party Runtime Dependencies**: Built entirely with Python's standard library (`socket`, `ssl`, `struct`, `hashlib`).

> [!WARNING]
> **Non-FIPS Notice**: This library is an independent open-source interoperability and verification tool. It is not certified under FIPS 140-3 and has not undergone CMVP validation.

---

## Installation

```bash
pip install pqblocks-tls-interop
```

No external cryptographic libraries or C compilers are required.

---

## Quickstart

### Python API

```python
from pqblocks_tls_interop import derive_shared_secret_10024, derive_key_material_rfc9954
from pqblocks_tls_interop.verifier.probe import HybridGroupProbe

# 1. Inspect RFC 10024 shared secret specifications
layout = HybridGroupProbe.get_shared_secret_layout()
print(layout["group_name"])  # X25519MLKEM768
print(layout["codepoint"])   # 4588

# 2. Derive combined hybrid shared secret (64 bytes: 32 bytes ML-KEM || 32 bytes X25519)
classical_ss = b"\x01" * 32
mlkem_ss = b"\x02" * 32
combined = derive_shared_secret_10024(classical_ss, mlkem_ss)
assert combined == mlkem_ss + classical_ss

# 3. Derive key material per RFC 9954 (48-byte SHA-384 digest)
km = derive_key_material_rfc9954(classical_ss, mlkem_ss)
assert len(km) == 48

# 4. Probe an external endpoint
probe = HybridGroupProbe("example.com", port=443, timeout=5.0)
result = probe.probe(sni="example.com")
if result.downgrade_detected:
    print(f"Warning: Endpoint downgraded to classical ({result.error_reason})")
```

### Command Line Interface

```bash
# Print RFC 10024 wire format layout
pqblocks-tls-interop --layout

# Probe a TLS server
pqblocks-tls-interop example.com -p 443 --sni example.com
```

#### CLI Exit Codes

- `0`: Hybrid group successfully negotiated (or `--layout` printed).
- `1`: Hybrid group not offered or downgrade to classical detected.
- `2`: Network operational error or invalid arguments.

---

## Performance Summary

Measured on Linux x86_64 across 1,000 iterations:

| Operation | Standard | Latency (Mean) | Throughput |
|---|---|---|---|
| `derive_shared_secret_10024` | RFC 10024 | 0.00021 ms | ~4,700,000 ops/sec |
| `derive_key_material_rfc9954` | RFC 9954 | 0.00264 ms | ~379,000 ops/sec |
| `get_shared_secret_layout` | RFC 10024 | 0.00040 ms | ~2,470,000 ops/sec |
| `ProbeResult.to_json` | JSON Serializer | 0.00474 ms | ~210,000 ops/sec |

For complete benchmark methodology, see [BENCHMARKS.md](BENCHMARKS.md).

---

## Security & Verification

- Tested against official NIST ACVP server ML-KEM decapsulation test vectors (`ML-KEM-encapDecap-FIPS203`).
- 235 automated unit and integration tests covering wire format parsing, SNI transport, downgrade detection, and edge cases.
- 99% statement coverage across codebase.

For details, see [SECURITY_NOTES.md](SECURITY_NOTES.md) and [TESTING.md](TESTING.md).

---

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE) for details.
