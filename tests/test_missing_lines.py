"""
Tests for missing coverage lines in probe.py.
"""

import sys
import socket
from unittest.mock import patch, MagicMock

# Ensure we can import the module
sys.path.insert(0, '../src')

from pqblocks_tls_interop.verifier.probe import HybridGroupProbe, ProbeResult


class TestProbeManualCoverage:
    """Test the _probe_manual method to cover missing lines."""

    def test_probe_manual_socket_creation_else_branch(self):
        """Cover line 208: else branch when socket.create_connection returns non-tuple."""
        probe = HybridGroupProbe("example.com")

        # Mock _build_client_hello to return a value so we proceed to socket creation
        with patch.object(probe, '_build_client_hello', return_value=b"client_hello"):
            # Mock socket.create_connection to return a direct socket (not a tuple)
            mock_sock = MagicMock()
            with patch('socket.create_connection', return_value=mock_sock):
                # Mock SSLContext to avoid SSL errors
                with patch('ssl.SSLContext') as mock_ssl_ctx:
                    mock_ssl_ctx.return_value = MagicMock()
                    # Make both send attempts succeed
                    mock_sock.send.side_effect = [None, None]
                    # Make recv return successful response
                    mock_sock.recv.return_value = b"ServerHello with X25519MLKEM768 data"
                    
                    result = probe._probe_manual()
                    
                    # Should succeed and parse the response - this means we took the else branch
                    # at line 207-208 where we checked if result is tuple
                    assert result.group_codepoint == 4588
                    assert result.mlkem_shared_first is True

    def test_probe_manual_socket_timeout(self):
        """Cover line 210: socket.timeout exception."""
        probe = HybridGroupProbe("example.com", timeout=0.001)

        # Mock _build_client_hello to return a value so we proceed to socket creation
        with patch.object(probe, '_build_client_hello', return_value=b"client_hello"):
            # Mock socket.create_connection to raise timeout
            with patch('socket.create_connection', side_effect=socket.timeout()):
                result = probe._probe_manual()
                
                # Should return timeout error
                assert result.error_reason == "timeout"

    def test_probe_manual_connection_refused(self):
        """Cover line 211: ConnectionRefusedError exception."""
        probe = HybridGroupProbe("example.com")

        # Mock _build_client_hello to return a value so we proceed to socket creation
        with patch.object(probe, '_build_client_hello', return_value=b"client_hello"):
            # Mock socket.create_connection to raise ConnectionRefusedError
            with patch('socket.create_connection', side_effect=ConnectionRefusedError()):
                result = probe._probe_manual()
                
                # Should return connection_refused error
                assert result.error_reason == "connection_refused"

    def test_probe_manual_generic_exception(self):
        """Cover lines 213-214: generic Exception exception handling."""
        probe = HybridGroupProbe("example.com")

        # Mock _build_client_hello to return a value so we proceed to socket creation
        with patch.object(probe, '_build_client_hello', return_value=b"client_hello"):
            # Mock socket.create_connection to raise a generic Exception
            with patch('socket.create_connection', side_effect=RuntimeError("Generic socket error")):
                result = probe._probe_manual()
                
                # Should return probe_error with the exception message
                assert result.error_reason == "probe_error: Generic socket error"

    def test_probe_manual_send_error_first_attempt(self):
        """Cover lines 225-227: first send error handling."""
        probe = HybridGroupProbe("example.com")

        # Mock _build_client_hello to return a value
        with patch.object(probe, '_build_client_hello', return_value=b"client_hello"):
            # Mock successful socket creation
            mock_sock = MagicMock()
            with patch('socket.create_connection', return_value=(mock_sock, ('127.0.0.1', 443))):
                # Mock SSLContext creation
                with patch('ssl.SSLContext'):
                    # Make the FIRST send attempt raise an Exception
                    mock_sock.send.side_effect = Exception("Send failed")
                    
                    result = probe._probe_manual()
                    
                    # Should return send_failed error from first attempt
                    assert result.error_reason == "probe_error: send_failed"
                    # Socket should be closed due to the exception
                    mock_sock.close.assert_called()

    def test_probe_manual_send_error_second_attempt(self):
        """Cover lines 238-240: second send error handling."""
        probe = HybridGroupProbe("example.com")

        # Mock _build_client_hello to return a value
        with patch.object(probe, '_build_client_hello', return_value=b"client_hello"):
            # Mock successful socket creation
            mock_sock = MagicMock()
            with patch('socket.create_connection', return_value=(mock_sock, ('127.0.0.1', 443))):
                # Mock SSLContext creation
                with patch('ssl.SSLContext') as mock_ssl_ctx:
                    mock_ssl_ctx.return_value = MagicMock()
                    # Make the FIRST send succeed (no exception) so we reach the second attempt
                    mock_sock.send.side_effect = [None, Exception("Send failed on second attempt")]
                    
                    result = probe._probe_manual()
                    
                    # Should return send_failed error from second attempt
                    assert result.error_reason == "probe_error: send_failed"
                    # Socket should be closed due to the exception
                    mock_sock.close.assert_called()

    def test_probe_manual_recv_error(self):
        """Cover lines 244-246: recv error handling."""
        probe = HybridGroupProbe("example.com")

        # Mock _build_client_hello to return a value
        with patch.object(probe, '_build_client_hello', return_value=b"client_hello"):
            # Mock successful socket creation
            mock_sock = MagicMock()
            with patch('socket.create_connection', return_value=(mock_sock, ('127.0.0.1', 443))):
                # Mock SSLContext creation
                with patch('ssl.SSLContext') as mock_ssl_ctx:
                    mock_ssl_ctx.return_value = MagicMock()
                    # Make both send attempts succeed
                    mock_sock.send.side_effect = [None, None]
                    # Make recv raise an Exception
                    mock_sock.recv.side_effect = Exception("Recv failed")
                    
                    result = probe._probe_manual()
                    
                    # Should return recv_failed error
                    assert result.error_reason == "probe_error: recv_failed"
                    # Socket should be closed due to the exception
                    mock_sock.close.assert_called()


class TestMainGuard:
    """Test the __main__ guard to cover line 335."""

    def test_main_guard_coverage(self):
        """Cover line 335: sys.exit(main()) by running the module as a script."""
        import subprocess
        
        # Run the probe module as a script with --layout to trigger __main__ guard
        # We need to set PYTHONPATH to include the src directory
        import os
        from pathlib import Path
        env = os.environ.copy()
        src_dir = str(Path(__file__).resolve().parent.parent / "src")
        if os.path.isdir(src_dir):
            env['PYTHONPATH'] = f"{src_dir}:{env.get('PYTHONPATH', '')}"
        result = subprocess.run([
            sys.executable,
            '-m',
            'pqblocks_tls_interop.verifier.probe',
            '--layout',
            'dummyhost'
        ],
        
        capture_output=True,
        text=True,
        timeout=10,
        env=env
        )
        
        # Should succeed (exit code 0) and output JSON
        assert result.returncode == 0
        assert '"group_name": "X25519MLKEM768"' in result.stdout
        assert '"codepoint": 4588' in result.stdout


if __name__ == "__main__":
    # When run directly, also test the __main__ guard in this test file
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))