"""Tests for pqblocks_tls_interop.verifier HybridGroupProbe - RFC 10024 X25519MLKEM768."""

import json
import sys
sys.path.insert(0, '../src')

from pqblocks_tls_interop.verifier.probe import (
    HybridGroupProbe,
    ProbeResult,
    HYBRID_GROUP_CODEPOINT,
    CLIENT_KEY_EXCHANGE_LEN,
    SERVER_KEY_EXCHANGE_LEN,
    SHARED_SECRET_LEN,
)
from pqblocks_tls_interop.interop import derive_shared_secret_10024, derive_key_material_rfc9954


class TestProbeResult:
    """Tests for ProbeResult dataclass."""

    def test_probe_result_default(self):
        """Test ProbeResult with default values."""
        result = ProbeResult()
        assert result.group_codepoint is None
        assert result.mlkem_shared_first is None
        assert result.downgrade_detected is False
        assert result.error_reason is None

    def test_probe_result_with_values(self):
        """Test ProbeResult with all fields set."""
        result = ProbeResult(
            group_codepoint=4588,
            mlkem_shared_first=True,
            downgrade_detected=False,
            error_reason=None
        )
        assert result.group_codepoint == 4588
        assert result.mlkem_shared_first is True
        assert result.downgrade_detected is False
        assert result.error_reason is None

    def test_probe_result_to_json(self):
        """Test ProbeResult JSON serialization."""
        result = ProbeResult(
            group_codepoint=4588,
            mlkem_shared_first=True,
            downgrade_detected=False,
            error_reason=None
        )
        json_str = result.to_json()
        parsed = json.loads(json_str)
        assert parsed["group_codepoint"] == 4588
        assert parsed["mlkem_shared_first"] is True
        assert parsed["downgrade_detected"] is False
        assert parsed["error_reason"] is None

    def test_probe_result_to_dict(self):
        """Test ProbeResult dict conversion."""
        result = ProbeResult(group_codepoint=4588)
        d = result.to_dict()
        assert isinstance(d, dict)
        assert d["group_codepoint"] == 4588


class TestHybridGroupProbe:
    """Tests for HybridGroupProbe class."""

    def test_probe_initialization(self):
        """Test probe initialization with defaults."""
        probe = HybridGroupProbe("example.com")
        assert probe.host == "example.com"
        assert probe.port == 443
        assert probe.timeout == 10.0

    def test_probe_initialization_custom(self):
        """Test probe initialization with custom values."""
        probe = HybridGroupProbe("example.com", port=8443, timeout=5.0)
        assert probe.host == "example.com"
        assert probe.port == 8443
        assert probe.timeout == 5.0

    def test_get_shared_secret_layout(self):
        """Test RFC 10024 shared secret layout output."""
        layout = HybridGroupProbe.get_shared_secret_layout()
        
        assert layout["group_name"] == "X25519MLKEM768"
        assert layout["codepoint"] == 4588
        assert layout["client_key_exchange_bytes"] == 1216
        assert layout["server_key_exchange_bytes"] == 1120
        assert layout["shared_secret_bytes"] == 64
        assert layout["concatenation_order"] == "mlkem_shared_secret || x25519_shared_secret"
        assert layout["mlkem_shared_first"] is True
        assert layout["mlkem_shared_secret_bytes"] == 32
        assert layout["x25519_shared_secret_bytes"] == 32
        assert layout["mlkem_encapsulation_bytes"] == 1184
        assert layout["mlkem_ciphertext_bytes"] == 1088
        assert layout["x25519_ephemeral_bytes"] == 32
        assert layout["hkdf_hash"] == "SHA-384"
        assert "RFC 10024" in layout["reference"]

    def test_probe_constants(self):
        """Test RFC 10024 constants are correct."""
        assert HYBRID_GROUP_CODEPOINT == 4588
        assert CLIENT_KEY_EXCHANGE_LEN == 1216  # 1184 + 32
        assert SERVER_KEY_EXCHANGE_LEN == 1120  # 1088 + 32
        assert SHARED_SECRET_LEN == 64  # 32 + 32


class TestRFC10024Concatenation:
    """Tests for RFC 10024 shared secret concatenation (not XOR)."""

    def test_derive_shared_secret_10024_basic(self):
        """Test basic concatenation of two 32-byte secrets."""
        classical = b"c" * 32
        pq = b"p" * 32
        
        result = derive_shared_secret_10024(classical, pq)
        
        assert len(result) == 64
        assert result[:32] == pq  # ML-KEM first
        assert result[32:] == classical  # X25519 second

    def test_derive_shared_secret_10024_order(self):
        """Test that ML-KEM shared secret comes FIRST per RFC 10024."""
        import hashlib
        
        classical_shared = hashlib.sha256(b"classical").digest()
        pq_shared = hashlib.sha256(b"pq").digest()
        
        combined = derive_shared_secret_10024(classical_shared, pq_shared)
        
        # First 32 bytes should be ML-KEM
        assert combined[:32] == pq_shared
        # Last 32 bytes should be X25519
        assert combined[32:] == classical_shared

    def test_derive_shared_secret_10024_not_xor(self):
        """Test that result is NOT XOR (forbidden by spec)."""
        classical = b"\x01" * 32
        pq = b"\x02" * 32
        
        # XOR result would be 0x03 * 32
        xor_result = bytes(a ^ b for a, b in zip(classical, pq))
        
        # Concatenation result should be different
        concat_result = derive_shared_secret_10024(classical, pq)
        
        assert concat_result != xor_result
        assert len(concat_result) == 64  # Concatenation is 64 bytes
        assert len(xor_result) == 32  # XOR is 32 bytes

    def test_derive_shared_secret_10024_invalid_classical_length(self):
        """Test error on invalid classical shared secret length."""
        try:
            derive_shared_secret_10024(b"short", b"p" * 32)
            assert False, "Should have raised ValueError"
        except ValueError as e:
            assert "32 bytes" in str(e)

    def test_derive_shared_secret_10024_invalid_pq_length(self):
        """Test error on invalid PQ shared secret length."""
        try:
            derive_shared_secret_10024(b"c" * 32, b"short")
            assert False, "Should have raised ValueError"
        except ValueError as e:
            assert "32 bytes" in str(e)


class TestRFC9954Combining:
    """Tests for RFC 9954 KEM combining algorithm."""

    def test_derive_key_material_rfc9954_basic(self):
        """Test RFC 9954 XOR + SHA-384 combining."""
        classical = b"c" * 32
        pq = b"p" * 32
        
        result = derive_key_material_rfc9954(classical, pq)
        
        # SHA-384 produces 48 bytes
        assert len(result) == 48
        
        # Should be deterministic
        result2 = derive_key_material_rfc9954(classical, pq)
        assert result == result2

    def test_derive_key_material_rfc9954_xor_then_hash(self):
        """Test that combining is XOR then SHA-384."""
        import hashlib
        
        classical = b"\x01" * 32
        pq = b"\x02" * 32
        
        # Manual XOR then SHA-384
        xored = bytes(a ^ b for a, b in zip(classical, pq))
        expected = hashlib.sha384(xored).digest()
        
        result = derive_key_material_rfc9954(classical, pq)
        assert result == expected

    def test_rfc9954_vs_rfc10024_different(self):
        """Test that RFC 9954 combining produces different result than RFC 10024 storage."""
        classical = b"c" * 32
        pq = b"p" * 32
        
        # RFC 10024 storage format (concatenation)
        storage = derive_shared_secret_10024(classical, pq)
        
        # RFC 9954 combining (XOR + hash)
        combining = derive_key_material_rfc9954(classical, pq)
        
        assert storage != combining
        assert len(storage) == 64  # Concatenation
        assert len(combining) == 48  # SHA-384 output


class TestParseOpenSSLOutput:
    """Tests for OpenSSL output parsing (if implemented)."""

    def test_hybrid_group_detection(self):
        """Test detection of hybrid group in output."""
        probe = HybridGroupProbe("example.com")
        
        # Output with hybrid group
        output = "Key-Exchange: X25519MLKEM768"
        result = probe._parse_openssl_output(output)
        
        assert result.group_codepoint == 4588
        assert result.mlkem_shared_first is True
        assert result.downgrade_detected is False

    def test_classical_only_detection(self):
        """Test detection of classical-only (downgrade)."""
        probe = HybridGroupProbe("example.com")
        
        # Output with classical X25519 only
        output = "Key-Exchange: X25519"
        result = probe._parse_openssl_output(output)
        
        assert result.group_codepoint == 29
        assert result.downgrade_detected is True
        assert result.error_reason == "downgrade-to-classical"

    def test_no_hybrid_group_offered(self):
        """Test detection when hybrid group not offered."""
        probe = HybridGroupProbe("example.com")
        
        output = "Key-Exchange: X25519, X25519MLKEM512"
        result = probe._parse_openssl_output(output)
        
        # Should detect downgrade since X25519MLKEM768 not present
        assert result.downgrade_detected is True
        assert result.error_reason == "hybrid_group_not_offered"


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))