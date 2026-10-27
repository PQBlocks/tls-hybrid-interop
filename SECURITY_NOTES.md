# Security Notes: pqblocks-tls-interop

This document describes the security posture, assumptions, and architectural properties of `pqblocks-tls-interop`.

---

## 1. Scope & Architecture

`pqblocks-tls-interop` is an auditing and compliance probe. It does not establish session keys for application data transfer and does not encrypt application traffic. It validates that the TLS negotiation layer offers and selects standardized post-quantum hybrid groups.

---

## 2. Cryptographic Combiner (RFC 10024 & RFC 9954)

The library provides reference implementations of standardized hybrid key derivation helpers:
- **RFC 10024 Section 4.3**: The combined shared secret is formed by concatenating the 32-byte ML-KEM shared secret *first*, followed by the 32-byte X25519 shared secret:
  ```
  combined_ss = mlkem_shared_secret || x25519_shared_secret (64 bytes total)
  ```
  The order is critical: placing classical first violates RFC 10024 and causes interoperability failures with OpenSSL 3.5+ and BoringSSL.
- **RFC 9954**: Key material derivation via SHA-384 over the XOR of components.

---

## 3. Network & Transport Security

- **OpenSSL Subprocess**: The probe invokes OpenSSL's `s_client` command line tool under strict timeout constraints. Command arguments are sanitized to prevent shell injection.
- **Connection Isolation**: Each probe runs in a distinct socket connection; no state or cached session tickets are persisted across runs.

---

## 4. Anti-Downgrade Enforcement

- The probe explicitly identifies classical fallback (e.g. server selects group `29` / X25519 or group `23` / secp256r1) when hybrid groups were advertised.
- In automated test and CI modes, any classical fallback surfaces as a non-zero exit code (`1`), preventing silent security downgrades.
