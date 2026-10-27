# AI & Automation Guide: pqblocks-tls-interop

This guide provides operational patterns and constraints for AI agents interacting with or generating code using `pqblocks-tls-interop`.

---

## Package Overview & Imports

```python
from pqblocks_tls_interop import (
    derive_shared_secret_10024,
    derive_key_material_rfc9954,
)
from pqblocks_tls_interop.verifier.probe import (
    HybridGroupProbe,
    ProbeResult,
    HYBRID_GROUP_CODEPOINT,
    HYBRID_GROUP_NAME,
)
```

---

## Safe Coding Patterns

### 1. Combining Shared Secrets
Inputs must be exactly 32 bytes each:
```python
classical_ss = b"..." # 32 bytes from X25519
mlkem_ss = b"..."     # 32 bytes from ML-KEM-768

# Returns 64 bytes: mlkem_ss || classical_ss
combined = derive_shared_secret_10024(classical_ss, mlkem_ss)
```

### 2. Probing Endpoints Programmatically
Always configure a reasonable network timeout:
```python
probe = HybridGroupProbe("api.example.com", port=443, timeout=5.0)
result = probe.probe(sni="api.example.com")

if result.downgrade_detected:
    # Server negotiated classical only
    handle_downgrade(result.group_codepoint)
elif result.error_reason:
    # Network or handshake error
    handle_error(result.error_reason)
elif result.group_codepoint == 4588:
    # Compliant RFC 10024 hybrid group
    proceed_with_pqc_pipeline()
```

### 3. CLI Scripting
When calling the CLI from bash or CI pipelines:
```bash
pqblocks-tls-interop "$HOST" -p "$PORT" --sni "$SNI"
EXIT_CODE=$?
if [ $EXIT_CODE -ne 0 ]; then
  echo "TLS endpoint does not support X25519MLKEM768 hybrid group!"
  exit 1
fi
```

---

## Prohibited Patterns

1. **Do NOT Swap Concatenation Order**: Under RFC 10024, the ML-KEM secret MUST be first. Passing `derive_shared_secret_10024(mlkem, classical)` will result in invalid key derivation.
2. **Do NOT Hardcode Non-Standard Codepoints**: Always reference `HYBRID_GROUP_CODEPOINT` (`4588`).
