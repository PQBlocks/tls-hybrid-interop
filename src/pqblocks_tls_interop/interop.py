import hashlib

SHARED_SECRET_MLKEM_FIRST = 64

def derive_shared_secret_10024(classical_shared: bytes, pq_shared: bytes) -> bytes:
    if len(classical_shared) != 32:
        raise ValueError(f"Classical shared secret must be 32 bytes, got {len(classical_shared)}")
    if len(pq_shared) != 32:
        raise ValueError(f"PQ shared secret must be 32 bytes, got {len(pq_shared)}")
    combined = pq_shared + classical_shared
    if len(combined) != SHARED_SECRET_MLKEM_FIRST:
        raise ValueError(f"Combined shared secret must be {SHARED_SECRET_MLKEM_FIRST} bytes, got {len(combined)}")
    return combined

def derive_key_material_rfc9954(classical_shared: bytes, pq_shared: bytes) -> bytes:
    xored = bytes(a ^ b for a, b in zip(classical_shared, pq_shared))
    key_material = hashlib.sha384(xored).digest()
    return key_material
