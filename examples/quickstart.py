"""Quickstart example for pqblocks-tls-interop."""
import json
from pqblocks_tls_interop import derive_shared_secret_10024, derive_key_material_rfc9954
from pqblocks_tls_interop.verifier.probe import HybridGroupProbe, HYBRID_GROUP_CODEPOINT, HYBRID_GROUP_NAME

def main():
    print("1. RFC 10024 Hybrid Group Parameters:")
    print(f"   Name: {HYBRID_GROUP_NAME}")
    print(f"   Codepoint: {HYBRID_GROUP_CODEPOINT} (0x11EC)")

    print("\n2. Querying RFC 10024 Shared Secret Layout:")
    layout = HybridGroupProbe.get_shared_secret_layout()
    print(json.dumps(layout, indent=2))

    print("\n3. Deriving Combined Shared Secret (RFC 10024):")
    classical_shared = b"\x01" * 32  # 32 bytes X25519
    pq_shared = b"\x02" * 32         # 32 bytes ML-KEM-768
    combined = derive_shared_secret_10024(classical_shared, pq_shared)
    print(f"   Combined length: {len(combined)} bytes")
    # In RFC 10024, ML-KEM is first in concatenation
    assert combined[:32] == pq_shared
    assert combined[32:] == classical_shared
    print("   ML-KEM-first concatenation verified.")

    print("\n4. Deriving Key Material (RFC 9954):")
    key_material = derive_key_material_rfc9954(classical_shared, pq_shared)
    print(f"   Derived key material length: {len(key_material)} bytes (SHA-384)")
    assert len(key_material) == 48

    print("\nQuickstart completed successfully.")

if __name__ == "__main__":
    main()
