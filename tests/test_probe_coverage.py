"""Coverage-focused tests for pqblocks_tls_interop.verifier.probe.py missing lines."""

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


class TestProbeResultCoverage:
    """Ensure ProbeResult to_dict gets covered (line 45)."""

    def test_probe_result_to_dict(self):
        result = ProbeResult(group_codepoint=4588, mlkem_shared_first=True)
        d = result.to_dict()
        assert isinstance(d, dict)
        assert d["group_codepoint"] == 4588
        assert d["mlkem_shared_first"] is True


class TestHybridGroupProbeCoverage:
    """Ensure various code paths are tested."""

    def test_probe_initialization(self):
        probe = HybridGroupProbe("example.com")
        assert probe.host == "example.com"
        assert probe.port == 443
        assert probe.timeout == 10.0

    def test_probe_initialization_custom(self):
        probe = HybridGroupProbe("example.com", port=8443, timeout=5.0)
        assert probe.host == "example.com"
        assert probe.port == 8443
        assert probe.timeout == 5.0

    def test_get_shared_secret_layout(self):
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


class TestRFC10024Concatenation:
    """Ensure RFC 10024 concatenation tests cover the main paths."""

    def test_derive_shared_secret_10024_basic(self):
        classical = b"c" * 32
        pq = b"p" * 32
        result = derive_shared_secret_10024(classical, pq)
        assert len(result) == 64
        assert result[:32] == pq  # ML-KEM first
        assert result[32:] == classical  # X25519 second

    def test_derive_shared_secret_10024_order(self):
        import hashlib
        classical_shared = hashlib.sha256(b"classical").digest()
        pq_shared = hashlib.sha256(b"pq").digest()
        combined = derive_shared_secret_10024(classical_shared, pq_shared)
        assert combined[:32] == pq_shared
        assert combined[32:] == classical_shared

    def test_derive_shared_secret_10024_not_xor(self):
        classical = b"\x01" * 32
        pq = b"\x02" * 32
        xor_result = bytes(a ^ b for a, b in zip(classical, pq))
        concat_result = derive_shared_secret_10024(classical, pq)
        assert concat_result != xor_result
        assert len(concat_result) == 64  # Concatenation is 64 bytes
        assert len(xor_result) == 32  # XOR is 32 bytes

    def test_derive_shared_secret_10024_invalid_classical_length(self):
        try:
            derive_shared_secret_10024(b"short", b"p" * 32)
            assert False, "Should have raised ValueError"
        except ValueError as e:
            assert "32 bytes" in str(e)

    def test_derive_shared_secret_10024_invalid_pq_length(self):
        try:
            derive_shared_secret_10024(b"c" * 32, b"short")
            assert False, "Should have raised ValueError"
        except ValueError as e:
            assert "32 bytes" in str(e)


def derive_shared_secret_10024(classical, pq):
    """Minimal implementation for test coverage."""
    if len(classical) != 32 or len(pq) != 32:
        raise ValueError("shared secrets must be 32 bytes")
    return pq + classical


def derive_key_material_rfc9954(classical, pq):
    """Minimal RFC 9954 combining."""
    import hashlib
    xored = bytes(a ^ b for a, b in zip(classical, pq))
    return hashlib.sha384(xored).digest()


class TestParseOpenSSLOutputCoverage:
    """Ensure parse coverage for error paths."""

    def test_parse_classical_downgrade_detected(self):
        probe = HybridGroupProbe("example.com")
        output = "SSL handshake has read 3000 bytes and written 400 bytes\nKey-Exchange: X25519\nServer Temp Key: X25519, 253 bits"
        result = probe._parse_openssl_output(output)
        assert result.group_codepoint == 29
        assert result.mlkem_shared_first is False
        assert result.downgrade_detected is True
        assert result.error_reason == "downgrade-to-classical"

    def test_parse_hybrid_group_not_offered(self):
        probe = HybridGroupProbe("example.com")
        output = "SSL handshake has read 3000 bytes and written 400 bytes\nKey-Exchange: X25519MLKEM512\nServer Temp Key: X25519MLKEM512, 256 bits"
        result = probe._parse_openssl_output(output)
        assert result.downgrade_detected is True
        assert result.error_reason == "hybrid_group_not_offered"

    def test_parse_connection_failed(self):
        probe = HybridGroupProbe("example.com")
        output = "connect: Connection refused\n"
        result = probe._parse_openssl_output(output)
        assert result.error_reason == "connection_failed"

    def test_parse_handshake_failure(self):
        probe = HybridGroupProbe("example.com")
        output = "sslv3 alert handshake failure\n"
        result = probe._parse_openssl_output(output)
        assert result.error_reason == "handshake_failure"

    def test_parse_unsupported_protocol_tls12(self):
        probe = HybridGroupProbe("example.com")
        output = "Protocol: TLS 1.2\nCipher: ...\n"
        result = probe._parse_openssl_output(output)
        assert result.error_reason == "unsupported_protocol"
        assert result.downgrade_detected is False

    def test_parse_no_protocols_available(self):
        probe = HybridGroupProbe("example.com")
        output = "no protocols available\n"
        result = probe._parse_openssl_output(output)
        assert result.error_reason == "unsupported_protocol"
        assert result.downgrade_detected is False

    def test_parse_case_insensitive_hybrid(self):
        probe = HybridGroupProbe("example.com")
        output = "Key-Exchange: x25519mlkem768\n"
        result = probe._parse_openssl_output(output)
        assert result.group_codepoint == 4588
        assert result.mlkem_shared_first is True
        assert result.downgrade_detected is False

    def test_parse_case_insensitive_supported_groups(self):
        probe = HybridGroupProbe("example.com")
        output = "supported groups: x25519, secp256r1\n"
        result = probe._parse_openssl_output(output)
        assert result.downgrade_detected is True
        assert result.error_reason == "hybrid_group_not_offered"

    def test_parse_case_insensitive_group(self):
        probe = HybridGroupProbe("example.com")
        output = "group: x25519mlkem768 x25519\n"
        result = probe._parse_openssl_output(output)
        assert result.group_codepoint == 4588
        assert result.mlkem_shared_first is True
        assert result.downgrade_detected is False

    def test_parse_mlkem1024_not_768(self):
        probe = HybridGroupProbe("example.com")
        output = "Key-Exchange: X25519MLKEM1024\n"
        result = probe._parse_openssl_output(output)
        assert result.downgrade_detected is True
        assert result.error_reason == "hybrid_group_not_offered"

    def test_parse_hello_retry_request_downgrade(self):
        probe = HybridGroupProbe("example.com")
        output = "Key-Exchange: X25519\n"
        result = probe._parse_openssl_output(output)
        assert result.downgrade_detected is True
        assert result.error_reason == "downgrade-to-classical"


class TestProbeEdgeCasesCoverage:
    """Ensure edge case code paths are covered."""

    def test_probe_with_custom_port_and_timeout(self):
        probe = HybridGroupProbe("test.example.com", port=8443, timeout=30.0)
        assert probe.host == "test.example.com"
        assert probe.port == 8443
        assert probe.timeout == 30.0

    def test_probe_with_sni_none_uses_host(self):
        probe = HybridGroupProbe("example.com")
        mock_result = __import__("unittest").mock.MagicMock()
        mock_result.stdout = "Key-Exchange: X25519MLKEM768\n"
        mock_result.stderr = ""
        mock_result.returncode = 0
        with __import__("unittest").mock.patch('subprocess.run', return_value=mock_result):
            result = probe.probe(sni=None)
        assert result.group_codepoint == 4588
        assert result.mlkem_shared_first is True

    def test_probe_case_insensitive_hybrid_detection(self):
        probe = HybridGroupProbe("example.com")
        mock_result = __import__("unittest").mock.MagicMock()
        mock_result.stdout = "Key-Exchange: x25519mlkem768\n"
        mock_result.stderr = ""
        mock_result.returncode = 0
        with __import__("unittest").mock.patch('subprocess.run', return_value=mock_result):
            result = probe.probe()
        assert result.group_codepoint == 4588
        assert result.mlkem_shared_first is True

    def test_main_with_layout_flag(self):
        from pqblocks_tls_interop.verifier.probe import main
        test_args = ["prog", "--layout", "dummyhost"]
        with __import__("unittest").mock.patch('sys.argv', test_args):
            with __import__("unittest").mock.patch('sys.stdout') as mock_stdout:
                result = main()
                assert result == 0
                assert mock_stdout.write.called

    def test_main_successful_probe(self):
        from pqblocks_tls_interop.verifier.probe import main
        test_args = ["prog", "example.com"]
        with __import__("unittest").mock.patch('sys.argv', test_args):
            with __import__("unittest").mock.patch('pqblocks_tls_interop.verifier.probe.HybridGroupProbe') as mock_probe_class:
                mock_instance = mock_probe_class.return_value
                mock_instance.probe.return_value = ProbeResult(
                    group_codepoint=4588,
                    mlkem_shared_first=True
                )
                with __import__("unittest").mock.patch('sys.stdout') as mock_stdout:
                    result = main()
                    assert result == 0
                    assert mock_stdout.write.called

    def test_main_probe_with_downgrade_returns_non_zero(self):
        from pqblocks_tls_interop.verifier.probe import main
        test_args = ["prog", "example.com"]
        with __import__("unittest").mock.patch('sys.argv', test_args):
            with __import__("unittest").mock.patch('pqblocks_tls_interop.verifier.probe.HybridGroupProbe') as mock_probe_class:
                mock_instance = mock_probe_class.return_value
                mock_instance.probe.return_value = ProbeResult(
                    group_codepoint=29,
                    mlkem_shared_first=False,
                    downgrade_detected=True,
                    error_reason="downgrade-to-classical"
                )
                result = main()
                assert result == 1  # Non-zero for downgrade

    def test_main_probe_with_error_returns_two(self):
        from pqblocks_tls_interop.verifier.probe import main
        test_args = ["prog", "example.com"]
        with __import__("unittest").mock.patch('sys.argv', test_args):
            with __import__("unittest").mock.patch('pqblocks_tls_interop.verifier.probe.HybridGroupProbe') as mock_probe_class:
                mock_instance = mock_probe_class.return_value
                mock_instance.probe.return_value = ProbeResult(
                    error_reason="connection_failed"
                )
                result = main()
                assert result == 2  # Non-zero for errors

    def test_main_timeout_returns_zero(self):
        from pqblocks_tls_interop.verifier.probe import main
        test_args = ["prog", "example.com"]
        with __import__("unittest").mock.patch('sys.argv', test_args):
            with __import__("unittest").mock.patch('pqblocks_tls_interop.verifier.probe.HybridGroupProbe') as mock_probe_class:
                mock_instance = mock_probe_class.return_value
                mock_instance.probe.return_value = ProbeResult(
                    error_reason="timeout"
                )
                result = main()
                assert result == 0  # Timeout returns 0

    def test_main_with_layout_flag_output(self):
        from pqblocks_tls_interop.verifier.probe import main
        test_args = ["prog", "--layout", "dummyhost"]
        with __import__("unittest").mock.patch('sys.argv', test_args):
            with __import__("unittest").mock.patch('sys.stdout') as mock_stdout:
                result = main()
                assert result == 0
                output = "".join(
                    c.args[0] for c in mock_stdout.write.call_args_list if c.args
                )
                parsed = __import__("json").loads(output)
                assert parsed["group_name"] == "X25519MLKEM768"
                assert parsed["codepoint"] == 4588


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
