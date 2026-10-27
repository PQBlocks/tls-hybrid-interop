"""Self-contained official test vectors loader for pqblocks-tls-interop."""
import json
import os
from pathlib import Path

VECTORS_DIR = Path(__file__).parent / "vectors"


def load(name: str):
    """Load testGroups from vendored official NIST ACVP or Wycheproof test vectors."""
    name_lower = name.lower()
    for root, _, files in os.walk(VECTORS_DIR):
        for f in sorted(files):
            if f.endswith(".json"):
                stem = f[:-5].lower()
                if name_lower in stem or stem in name_lower:
                    p = os.path.join(root, f)
                    with open(p, "r", encoding="utf-8") as fh:
                        doc = json.load(fh)
                    return doc.get("testGroups", [])
    raise FileNotFoundError(f"Vector set {name} not found in {VECTORS_DIR}")
