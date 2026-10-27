"""
Integration tests for HybridGroupProbe - RFC 10024 X25519MLKEM768.

These tests focus on integration-style testing to improve coverage by testing
the actual probe logic with realistic OpenSSL output scenarios and error conditions.
"""

import sys
import subprocess
import socket
from unittest.mock import patch, MagicMock

sys.path.insert(0, '../src')

from pqblocks_tls_interop.verifier.probe import HybridGroupProbe, ProbeResult


class TestProbeIntegration:
    """Integration tests for HybridGroupProbe probe method."""

    def test_probe_successful_hybrid_group(self):
        """Test probe method with successful hybrid group detection."""
        probe = HybridGroupProbe("example.com")

        # Mock subprocess.run to return successful hybrid group output
        mock_result = MagicMock()
        mock_result.stdout = "SSL handshake has read 3000 bytes and written 400 bytes\n"
        mock_result.stdout += "Key-Exchange: X25519MLKEM768\n"
        mock_result.stdout += "Server Temp Key: X25519MLKEM768, 256 bits\n"
        mock_result.stderr = ""
        mock_result.returncode = 0

        with patch('subprocess.run', return_value=mock_result):
            result = probe.probe(sni="test.example.com")

            # Verify the probe detected hybrid group successfully
            assert result.group_codepoint == 4588
            assert result.mlkem_shared_first is True
            assert result.downgrade_detected is False
            assert result.error_reason is None

    def test_probe_timeout_handling(self):
        """Test probe method handles timeout correctly."""
        probe = HybridGroupProbe("example.com", timeout=1.0)

        # Mock subprocess.run to raise TimeoutExpired
        with patch('subprocess.run', side_effect=subprocess.TimeoutExpired(
                cmd=["openssl", "s_client"], timeout=1.0)):
            result = probe.probe()

            # Verify timeout handling
            assert result.error_reason == "timeout"
            assert result.downgrade_detected is False

    def test_probe_openssl_not_available(self):
        """Test probe when OpenSSL is not available."""
        probe = HybridGroupProbe("example.com")

        # Mock subprocess.run to raise FileNotFoundError
        with patch('subprocess.run', side_effect=FileNotFoundError()):
            result = probe.probe()

            # Verify OpenSSL not available handling
            assert result.error_reason == "openssl_not_available"

    def test_probe_fallback_to_manual_on_error(self):
        """Test probe falls back to manual parsing when OpenSSL returns error but no group detected."""
        probe = HybridGroupProbe("example.com")

        # First call returns output that results in NO error_reason AND NO group_codepoint
        # This happens when OpenSSL output doesn't match any error pattern and doesn't contain group info
        mock_openssl_result = MagicMock()
        mock_openssl_result.stdout = "Some unrelated output\n"
        mock_openssl_result.stderr = ""
        mock_openssl_result.returncode = 0

        # Mock _probe_manual to return a successful result
        with patch('subprocess.run', return_value=mock_openssl_result):
            with patch.object(probe, '_probe_manual') as mock_manual:
                mock_manual.return_value = ProbeResult(
                    group_codepoint=4588,
                    mlkem_shared_first=True,
                    downgrade_detected=False
                )

                result = probe.probe()

                # Verify fallback was called
                mock_manual.assert_called_once()
                assert result.group_codepoint == 4588


class TestParseOpenSSLOutputIntegration:
    """Integration tests for _parse_openssl_output method directly."""

    def test_parse_classical_downgrade_detected(self):
        """Test _parse_openssl_output detects classical downgrade."""
        probe = HybridGroupProbe("example.com")

        # Classical-only output
        output = "SSL handshake has read 3000 bytes and written 400 bytes\n"
        output += "Key-Exchange: X25519\n"
        output += "Server Temp Key: X25519, 253 bits\n"

        result = probe._parse_openssl_output(output)

        # Verify downgrade detection
        assert result.group_codepoint == 29  # X25519 codepoint
        assert result.mlkem_shared_first is False
        assert result.downgrade_detected is True
        assert result.error_reason == "downgrade-to-classical"

    def test_parse_hybrid_group_not_offered(self):
        """Test _parse_openssl_output when hybrid group not offered."""
        probe = HybridGroupProbe("example.com")

        # Different ML-KEM variant
        output = "SSL handshake has read 3000 bytes and written 400 bytes\n"
        output += "Key-Exchange: X25519MLKEM512\n"
        output += "Server Temp Key: X25519MLKEM512, 256 bits\n"

        result = probe._parse_openssl_output(output)

        # Should detect that X25519MLKEM768 is not offered
        assert result.downgrade_detected is True
        assert result.error_reason == "hybrid_group_not_offered"

    def test_parse_connection_failed(self):
        """Test _parse_openssl_output handles connection failure."""
        probe = HybridGroupProbe("example.com")

        output = "connect: Connection refused\n"

        result = probe._parse_openssl_output(output)

        assert result.error_reason == "connection_failed"

    def test_parse_handshake_failure(self):
        """Test _parse_openssl_output handles TLS handshake failure."""
        probe = HybridGroupProbe("example.com")

        output = "sslv3 alert handshake failure\n"

        result = probe._parse_openssl_output(output)

        assert result.error_reason == "handshake_failure"

    def test_parse_unsupported_protocol_tls12(self):
        """Test _parse_openssl_output detects TLS 1.2 as unsupported protocol."""
        probe = HybridGroupProbe("example.com")

        output = "Protocol: TLS 1.2\nCipher: ...\n"

        result = probe._parse_openssl_output(output)

        assert result.error_reason == "unsupported_protocol"
        assert result.downgrade_detected is False

    def test_parse_no_protocols_available(self):
        """Test _parse_openssl_output when no protocols are available."""
        probe = HybridGroupProbe("example.com")

        output = "no protocols available\n"

        result = probe._parse_openssl_output(output)

        assert result.error_reason == "unsupported_protocol"
        assert result.downgrade_detected is False

    def test_parse_supported_groups_detection(self):
        """Test _parse_openssl_output detects supported groups extension output."""
        probe = HybridGroupProbe("example.com")

        # Output with supported groups listing classical X25519
        output = "Supported Groups: X25519, secp256r1\n"

        result = probe._parse_openssl_output(output)

        # Current implementation detects X25519 first and reports classical downgrade
        assert result.downgrade_detected is True
        assert result.error_reason == "downgrade-to-classical"

    def test_parse_group_detection_failed(self):
        """Test _parse_openssl_output when group detection fails completely."""
        probe = HybridGroupProbe("example.com")

        output = "Some random output without group info\n"

        result = probe._parse_openssl_output(output)

        # Should fail to detect group (manual probe not implemented is the expected behavior for unrecognized output)
        assert result.error_reason == "manual_probe_not_implemented: Use OpenSSL s_client for probing"
        assert result.downgrade_detected is False

    def test_parse_tls11_unsupported(self):
        """Test _parse_openssl_output detects TLS 1.1 as unsupported protocol."""
        probe = HybridGroupProbe("example.com")

        output = "Protocol: TLS 1.1\n"

        result = probe._parse_openssl_output(output)

        assert result.error_reason == "unsupported_protocol"
        assert result.downgrade_detected is False

    def test_parse_tls10_unsupported(self):
        """Test _parse_openssl_output detects TLS 1.0 as unsupported protocol."""
        probe = HybridGroupProbe("example.com")

        output = "Protocol: TLS 1.0\n"

        result = probe._parse_openssl_output(output)

        assert result.error_reason == "unsupported_protocol"
        assert result.downgrade_detected is False

    def test_parse_case_insensitive_protocol(self):
        """Test _parse_openssl_output detects protocol case-insensitively."""
        probe = HybridGroupProbe("example.com")

        output = "protocol: tls 1.2\n"

        result = probe._parse_openssl_output(output)

        assert result.error_reason == "unsupported_protocol"
        assert result.downgrade_detected is False

    def test_parse_case_insensitive_hybrid(self):
        """Test _parse_openssl_output detects hybrid group case-insensitively."""
        probe = HybridGroupProbe("example.com")

        output = "Key-Exchange: x25519mlkem768\n"

        result = probe._parse_openssl_output(output)

        assert result.group_codepoint == 4588
        assert result.mlkem_shared_first is True
        assert result.downgrade_detected is False

    def test_parse_case_insensitive_supported_groups(self):
        """Test _parse_openssl_output detects supported groups case-insensitively."""
        probe = HybridGroupProbe("example.com")

        output = "supported groups: x25519, secp256r1\n"

        result = probe._parse_openssl_output(output)

        assert result.downgrade_detected is True
        assert result.error_reason == "hybrid_group_not_offered"

    def test_parse_case_insensitive_group(self):
        """Test _parse_openssl_output detects group: case-insensitively."""
        probe = HybridGroupProbe("example.com")

        output = "group: x25519mlkem768 x25519\n"

        result = probe._parse_openssl_output(output)

        assert result.group_codepoint == 4588
        assert result.mlkem_shared_first is True
        assert result.downgrade_detected is False

    def test_parse_mlkem1024_not_768(self):
        """Test _parse_openssl_output treats MLKEM1024 as not 768."""
        probe = HybridGroupProbe("example.com")

        output = "Key-Exchange: X25519MLKEM1024\n"

        result = probe._parse_openssl_output(output)

        assert result.downgrade_detected is True
        assert result.error_reason == "hybrid_group_not_offered"

    def test_parse_hello_retry_request_downgrade(self):
        """Test _parse_openssl_output handles HelloRetryRequest downgrade."""
        probe = HybridGroupProbe("example.com")

        output = "Key-Exchange: X25519\n"  # After HRR, hybrid removed

        result = probe._parse_openssl_output(output)

        assert result.downgrade_detected is True
        assert result.error_reason == "downgrade-to-classical"


class TestManualProbeIntegration:
    """Integration tests for manual probe fallback methods."""

    def test_probe_manual_timeout(self):
        """Test manual probe handles timeout - catches NotImplementedError first."""
        probe = HybridGroupProbe("example.com", timeout=0.001)  # Very short timeout

        # Mock socket to raise timeout, but _build_client_hello raises NotImplementedError first
        with patch('socket.socket') as mock_socket:
            mock_socket_instance = MagicMock()
            mock_socket_instance.connect.side_effect = socket.timeout()
            mock_socket.return_value = mock_socket_instance

            result = probe._probe_manual()

        # NotImplementedError from _build_client_hello is caught and returns manual_probe_not_implemented
        assert "manual_probe_not_implemented" in result.error_reason

    def test_probe_manual_connection_refused(self):
        """Test manual probe handles connection refused - catches NotImplementedError first."""
        probe = HybridGroupProbe("example.com")

        # Mock socket to raise ConnectionRefusedError, but _build_client_hello raises NotImplementedError first
        with patch('socket.socket') as mock_socket:
            mock_socket_instance = MagicMock()
            mock_socket_instance.connect.side_effect = ConnectionRefusedError()
            mock_socket.return_value = mock_socket_instance

            result = probe._probe_manual()

        # NotImplementedError from _build_client_hello is caught and returns manual_probe_not_implemented
        assert "manual_probe_not_implemented" in result.error_reason

    def test_build_client_hello_not_implemented(self):
        """Test that _build_client_hello raises NotImplementedError."""
        probe = HybridGroupProbe("example.com")

        try:
            probe._build_client_hello()
            assert False, "Should have raised NotImplementedError"
        except NotImplementedError:
            pass  # Expected

    def test_parse_server_hello_hybrid_detected(self):
        """Test _parse_server_hello detects hybrid group."""
        probe = HybridGroupProbe("example.com")

        # Test with hybrid group bytes
        result = probe._parse_server_hello(b"Some server hello with X25519MLKEM768 data")

        assert result.group_codepoint == 4588
        assert result.mlkem_shared_first is True

    def test_parse_server_hello_classical_downgrade(self):
        """Test _parse_server_hello detects classical downgrade."""
        probe = HybridGroupProbe("example.com")

        # Test with classical X25519 only
        result = probe._parse_server_hello(b"Server hello with X25519 only")

        assert result.group_codepoint == 29
        assert result.downgrade_detected is True
        assert result.error_reason == "downgrade-to-classical"

    def test_parse_server_hello_empty_response(self):
        """Test _parse_server_hello handles empty response."""
        probe = HybridGroupProbe("example.com")

        result = probe._parse_server_hello(b"")

        assert result.error_reason == "empty_response"

    def test_parse_server_hello_group_detection_failed(self):
        """Test _parse_server_hello when no recognizable data."""
        probe = HybridGroupProbe("example.com")

        result = probe._parse_server_hello(b"Random bytes without crypto indicators")

        assert result.error_reason == "group_detection_failed"

    def test_parse_server_hello_mlkem_lowercase(self):
        """Test _parse_server_hello detects mlkem case-insensitively."""
        probe = HybridGroupProbe("example.com")

        result = probe._parse_server_hello(b"server hello with mlkem data")

        assert result.group_codepoint == 4588
        assert result.mlkem_shared_first is True

    def test_parse_server_hello_with_mlkem_lowercase_not_768(self):
        """Test _parse_server_hello detects mlkem lowercase that's not 768."""
        probe = HybridGroupProbe("example.com")

        result = probe._parse_server_hello(b"server hello with mlkem512 data")

        assert result.downgrade_detected is True
        assert result.error_reason == "hybrid_group_not_offered"


class TestMainFunctionIntegration:
    """Integration tests for main CLI function."""

    def test_main_with_layout_flag(self):
        """Test main function with --layout flag."""
        from pqblocks_tls_interop.verifier.probe import main

        test_args = ["prog", "--layout", "dummyhost"]  # host is required

        with patch('sys.argv', test_args):
            with patch('sys.stdout') as mock_stdout:
                result = main()

                assert result == 0
                # Verify JSON layout was printed
                assert mock_stdout.write.called

    def test_main_successful_probe(self):
        """Test main function with successful probe."""
        from pqblocks_tls_interop.verifier.probe import main

        test_args = ["prog", "example.com"]

        with patch('sys.argv', test_args):
            with patch('pqblocks_tls_interop.verifier.probe.HybridGroupProbe') as mock_probe_class:
                mock_instance = mock_probe_class.return_value
                mock_instance.probe.return_value = ProbeResult(
                    group_codepoint=4588,
                    mlkem_shared_first=True
                )

                with patch('sys.stdout') as mock_stdout:
                    result = main()

                    assert result == 0
                    assert mock_stdout.write.called

    def test_main_probe_with_downgrade_returns_non_zero(self):
        """Test main function returns non-zero for downgrade."""
        from pqblocks_tls_interop.verifier.probe import main

        test_args = ["prog", "example.com"]

        with patch('sys.argv', test_args):
            with patch('pqblocks_tls_interop.verifier.probe.HybridGroupProbe') as mock_probe_class:
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
        """Test main function returns 2 for probe errors."""
        from pqblocks_tls_interop.verifier.probe import main

        test_args = ["prog", "example.com"]

        with patch('sys.argv', test_args):
            with patch('pqblocks_tls_interop.verifier.probe.HybridGroupProbe') as mock_probe_class:
                mock_instance = mock_probe_class.return_value
                mock_instance.probe.return_value = ProbeResult(
                    error_reason="connection_failed"
                )

                result = main()

                assert result == 2  # Non-zero for errors

    def test_main_timeout_returns_zero(self):
        """Test main function returns 0 for timeout (not treated as error)."""
        from pqblocks_tls_interop.verifier.probe import main

        test_args = ["prog", "example.com"]

        with patch('sys.argv', test_args):
            with patch('pqblocks_tls_interop.verifier.probe.HybridGroupProbe') as mock_probe_class:
                mock_instance = mock_probe_class.return_value
                mock_instance.probe.return_value = ProbeResult(
                    error_reason="timeout"
                )

                result = main()

                assert result == 0  # Timeout returns 0


class TestProbeEdgeCases:
    """Edge case tests for probe functionality."""

    def test_probe_with_custom_port_and_timeout(self):
        """Test probe initialization with custom port and timeout."""
        probe = HybridGroupProbe("test.example.com", port=8443, timeout=30.0)

        assert probe.host == "test.example.com"
        assert probe.port == 8443
        assert probe.timeout == 30.0

    def test_probe_with_sni_none_uses_host(self):
        """Test probe uses host as SNI when SNI is None."""
        probe = HybridGroupProbe("example.com")

        mock_result = MagicMock()
        mock_result.stdout = "Key-Exchange: X25519MLKEM768\n"
        mock_result.stderr = ""
        mock_result.returncode = 0

        with patch('subprocess.run', return_value=mock_result) as mock_run:
            result = probe.probe(sni=None)

            # Verify the command used the host as servername
            args, kwargs = mock_run.call_args
            cmd = args[0]
            assert "-servername" in cmd
            servername_index = cmd.index("-servername")
            assert cmd[servername_index + 1] == "example.com"

    def test_probe_case_insensitive_hybrid_detection(self):
        """Test probe detects hybrid group case-insensitively."""
        probe = HybridGroupProbe("example.com")

        mock_result = MagicMock()
        mock_result.stdout = "Key-Exchange: x25519mlkem768\n"
        mock_result.stderr = ""
        mock_result.returncode = 0

        with patch('subprocess.run', return_value=mock_result):
            result = probe.probe()

            assert result.group_codepoint == 4588
            assert result.mlkem_shared_first is True
            assert result.downgrade_detected is False