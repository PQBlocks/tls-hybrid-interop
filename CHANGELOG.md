# Changelog: pqblocks-tls-interop

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0] - 2026-10-26

### Added
- RFC 10024 hybrid group probe for TLS 1.3 `X25519MLKEM768` (codepoint `4588` / `0x11EC`).
- Automated detection of downgrade-to-classical (codepoint `29` / X25519) and non-hybrid server hellos.
- Combined shared secret derivation per RFC 10024 (ML-KEM shared secret first concatenation).
- Key material derivation helper per RFC 9954 (SHA-384 digest over XOR of shared components).
- Standalone CLI entrypoint `pqblocks-tls-interop` with `--layout`, `-p`, `--sni`, and `--timeout` flags.
- Comprehensive test suite with 235 passing automated tests.
- Full support across Python 3.11, 3.12, 3.13, and 3.14 with zero third-party runtime dependencies.
