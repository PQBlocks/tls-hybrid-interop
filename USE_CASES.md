# Use Cases & Integration Patterns: pqblocks-tls-interop

This document describes primary integration architectures and practical patterns for `pqblocks-tls-interop`.

---

## 1. Automated CI/CD Deployment Gates

### Challenge
DevSecOps teams must guarantee that ingress gateways, load balancers, and internal microservices enable post-quantum TLS before staging environments can be promoted to production.

### Solution
Use `pqblocks-tls-interop` as a mandatory CI/CD pipeline step. The command returns exit code `0` on hybrid success and `1` if the server only negotiates classical algorithms.

```yaml
# GitHub Actions / GitLab CI Job
- name: Verify Post-Quantum TLS Support
  run: |
    pqblocks-tls-interop api-staging.internal.net -p 443 --sni api-staging.internal.net
```

---

## 2. Infrastructure Inventory & Compliance Auditing

### Challenge
Security compliance engineers need to audit thousands of internal domain names and report whether they comply with post-quantum migration mandates (such as NSA CNSA 2.0).

### Solution
Write a Python script to scan inventory lists and aggregate JSON probe results:

```python
from pqblocks_tls_interop.verifier.probe import HybridGroupProbe

domains = ["auth.corp.com", "gateway.corp.com", "api.corp.com"]

for d in domains:
    probe = HybridGroupProbe(d, timeout=3.0)
    result = probe.probe(sni=d)
    if result.downgrade_detected:
        print(f"[VIOLATION] {d} negotiated classical codepoint {result.group_codepoint}")
    elif result.group_codepoint == 4588:
        print(f"[COMPLIANT] {d} negotiated X25519MLKEM768")
    else:
        print(f"[ERROR] {d}: {result.error_reason}")
```

---

## 3. Pre-Flight Configuration Verification

### Challenge
When upgrading OpenSSL or NGINX/Envoy configs to support hybrid groups, operators need rapid confirmation of the exact byte layout and codepoints expected by RFC 10024 without setting up packet captures.

### Solution
Use the `--layout` flag:

```bash
pqblocks-tls-interop --layout
```

Outputs full machine-readable JSON detailing exact client and server key exchange lengths (1216 and 1120 bytes) and concatenation ordering.
