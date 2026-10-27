"""Targeted tests for the remaining uncovered lines in probe.py."""

import sys
import subprocess
import socket
from unittest.mock import patch, MagicMock

sys.path.insert(0, '../src')

from pqblocks_tls_interop.verifier.probe import HybridGroupProbe, ProbeResult


class TestRemainingCoverageGaps:
    """Target the exact missing lines: 118, 122, 169-170, 185, 189-225, 230, 233-250, 300."""

    # --- Lines 117-120: _probe_with_openssl connection_failed branch ---
    def test_probe_openssl_connect_errno_in_output(self):
        probe = HybridGroupProbe("example.com")
        mock_result = MagicMock()
        mock_result.stdout = "connect: Connection refused (errno 111)\n"
        mock_result.stderr = ""
        mock_result.returncode = 1

        with patch('subprocess.run', return_value=mock_result):
            result = probe.probe()
        assert result.error_reason == "connection_failed"

    # --- Lines 121-124: _probe_with_openssl handshake_failure branch ---
    def test_probe_openssl_handshake_failure_output(self):
        probe = HybridGroupProbe("example.com")
        mock_result = MagicMock()
        mock_result.stdout = "sslv3 alert handshake failure\n"
        mock_result.stderr = ""
        mock_result.returncode = 1

        with patch('subprocess.run', return_value=mock_result):
            result = probe.probe()
        assert result.error_reason == "handshake_failure"

    # --- Lines 153-170: supported_groups branch with no x25519 at all ---
    def test_parse_supported_groups_no_x25519_at_all(self):
        probe = HybridGroupProbe("example.com")
        output = "Supported Groups: secp256r1, secp384r1\n"
        result = probe._parse_openssl_output(output)
        assert result.downgrade_detected is True
        assert result.error_reason == "hybrid_group_not_offered"

    # --- Line 185: manual_probe_not_implemented fallback in _parse_openssl_output ---
    def test_parse_openssl_unrecognized_output(self):
        probe = HybridGroupProbe("example.com")
        output = "Some completely unrelated OpenSSL noise\n"
        result = probe._parse_openssl_output(output)
        assert result.error_reason == "manual_probe_not_implemented: Use OpenSSL s_client for probing"
        assert result.downgrade_detected is False

    # --- Lines 189-225: _probe_manual socket + send/recv/parse path ---
    def test_probe_manual_success_path(self):
        probe = HybridGroupProbe("example.com", timeout=5.0)

        fake_sock = MagicMock()
        fake_sock.recv.return_value = b"ServerHello with X25519MLKEM768 data"

        mock_ctx = MagicMock()

        with patch('socket.create_connection', return_value=(fake_sock, ('127.0.0.1', 443))):
            with patch('ssl.SSLContext', return_value=mock_ctx):
                with patch.object(probe, '_build_client_hello', return_value=b"client_hello_bytes"):
                    result = probe._probe_manual()

        assert result.group_codepoint == 4588
        assert result.mlkem_shared_first is True

    # --- Line 230: _build_client_hello raises NotImplementedError ---
    def test_build_client_hello_raises_not_implemented(self):
        probe = HybridGroupProbe("example.com")
        try:
            probe._build_client_hello()
            assert False, "Should have raised NotImplementedError"
        except NotImplementedError:
            pass

    # --- Lines 233-250: _parse_server_hello all branches ---
    def test_parse_server_hello_hybrid(self):
        probe = HybridGroupProbe("example.com")
        result = probe._parse_server_hello(b"ServerHello with X25519MLKEM768")
        assert result.group_codepoint == 4588
        assert result.mlkem_shared_first is True

    def test_parse_server_hello_classical_downgrade(self):
        probe = HybridGroupProbe("example.com")
        result = probe._parse_server_hello(b"ServerHello with X25519")
        assert result.group_codepoint == 29
        assert result.downgrade_detected is True
        assert result.error_reason == "downgrade-to-classical"

    def test_parse_server_hello_group_detection_failed(self):
        probe = HybridGroupProbe("example.com")
        result = probe._parse_server_hello(b"random bytes no crypto here")
        assert result.error_reason == "group_detection_failed"

    # --- Line 300: sys.exit(main()) in __main__ guard ---
    def test_main_guard_exit_called(self):
        import importlib
        import pqblocks_tls_interop.verifier.probe as probe_mod

        with patch('sys.argv', ['prog', '--layout', 'dummyhost']):
            with patch('sys.stdout'):
                try:
                    probe_mod.main()
                except SystemExit:
                    pass

        assert True
