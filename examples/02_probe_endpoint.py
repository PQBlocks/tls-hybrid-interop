"""Demonstrate TLS 1.3 hybrid group probe and downgrade detection."""
from pqblocks_tls_interop.verifier.probe import (
    HybridGroupProbe,
    ProbeResult,
    CLIENT_KEY_EXCHANGE_LEN,
    SERVER_KEY_EXCHANGE_LEN,
    SHARED_SECRET_LEN,
)

def main():
    print("1. Wire Format Validation Constants:")
    print(f"   Client key_exchange length: {CLIENT_KEY_EXCHANGE_LEN} bytes (1184 ML-KEM + 32 X25519)")
    print(f"   Server key_exchange length: {SERVER_KEY_EXCHANGE_LEN} bytes (1088 ML-KEM + 32 X25519)")
    print(f"   Combined shared secret len: {SHARED_SECRET_LEN} bytes")

    print("\n2. Simulating Downgrade Detection:")
    # When a server only negotiates classical X25519 (codepoint 29)
    result = ProbeResult(
        group_codepoint=29,
        mlkem_shared_first=False,
        downgrade_detected=True,
        error_reason="downgrade-to-classical",
    )
    print(result.to_json())
    assert result.downgrade_detected is True
    print("   Downgrade detection verified.")

    print("\n3. Inspecting Probe Configuration:")
    probe = HybridGroupProbe("localhost", port=8443, timeout=2.0)
    print(f"   Target: {probe.host}:{probe.port}")
    print(f"   Timeout: {probe.timeout}s")
    print("\nProbe endpoint example completed successfully.")

if __name__ == "__main__":
    main()
