#!/usr/bin/env python3
"""
pqblocks-tls-interop.verifier.HybridGroupProbe - TLS Hybrid Group Probe Implementation
This module implements a verifier/probe for RFC 10024 X25519MLKEM768 hybrid group
negotiation in TLS 1.3. It probes TLS endpoints and validates their hybrid group
support, without implementing a TLS handshake.
RFC 10024 Compliance:
- Group codepoint: 4588 (0x11EC) for X25519MLKEM768
- Client key_exchange: ML-KEM-768 encapsulation (1184 bytes) || X25519 ephemeral share (32 bytes) = 1216 bytes
- Server key_exchange: ML-KEM-768 ciphertext (1088 bytes) || X25519 ephemeral share (32 bytes) = 1120 bytes
- Shared secret: ML-KEM shared secret (32 bytes) || X25519 shared secret (32 bytes) = 64 bytes
- ML-KEM shared secret is FIRST in concatenation (not XOR)
"""
import json
import subprocess
import sys
import socket
import ssl
import struct
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass, asdict
# RFC 10024 Constants
HYBRID_GROUP_CODEPOINT = 4588  # 0x11EC
HYBRID_GROUP_NAME = "X25519MLKEM768"
# Key exchange lengths per RFC 10024 Section 4.1, 4.2
CLIENT_KEY_EXCHANGE_LEN = 1216  # 1184 (ML-KEM-768 encap) + 32 (X25519)
SERVER_KEY_EXCHANGE_LEN = 1120  # 1088 (ML-KEM-768 ciphertext) + 32 (X25519)
SHARED_SECRET_LEN = 64  # 32 (ML-KEM) + 32 (X25519)
# Supported groups extension type (RFC 8446 Section 4.2.7)
SUPPORTED_GROUPS_EXT_TYPE = 10
# Key share extension type (RFC 8446 Section 4.2.8)
KEY_SHARE_EXT_TYPE = 51
@dataclass
class ProbeResult:
    """Result of a hybrid group probe."""
    group_codepoint: Optional[int] = None
    mlkem_shared_first: Optional[bool] = None
    downgrade_detected: bool = False
    error_reason: Optional[str] = None
    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(asdict(self), indent=2)
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)
class HybridGroupProbe:
    """
    Probes a TLS endpoint for X25519MLKEM768 hybrid group support per RFC 10024.
    This is a verifier/probe tool - it does NOT implement a TLS handshake.
    It uses OpenSSL's s_client to connect and parse the server's response.
    """
    def __init__(self, host: str, port: int = 443, timeout: float = 10.0):
        """
        Initialize the probe.
        Args:
            host: Target hostname or IP address
            port: Target port (default: 443)
            timeout: Connection timeout in seconds (default: 10.0)
        """
        self.host = host
        self.port = port
        self.timeout = timeout
    def probe(self, sni: Optional[str] = None) -> ProbeResult:
        """
        Probe the TLS endpoint for hybrid group support.
        Args:
            sni: Optional SNI value to send
        Returns:
            ProbeResult with group negotiation details
        """
        # First try using OpenSSL s_client
        result = self._probe_with_openssl(sni)
        # Return immediately if we got a definitive error in the subprocess call
        # (timeout, openssl_not_available, connection_failed)
        if result.error_reason in ("timeout", "openssl_not_available", "connection_failed"):
            return result
        # If we successfully detected the hybrid group, return.
        if result.group_codepoint == HYBRID_GROUP_CODEPOINT and result.error_reason is None:
            return result
        # If _parse_openssl_output gave us a definitive group detection (downgrade or hybrid not offered),
        # don't fall back to manual - return the parsed result.
        if result.group_codepoint is not None:
            return result
        # If _parse_openssl_output gave a specific error (not the fallback marker), return it
        if result.error_reason and result.error_reason != "manual_probe_not_implemented: Use OpenSSL s_client for probing":
            return result
        # Otherwise, fall back to manual parsing.
        return self._probe_manual(sni)
    def _probe_with_openssl(self, sni: Optional[str] = None) -> ProbeResult:
        """Probe using OpenSSL s_client."""
        cmd = [
            "openssl", "s_client",
            "-connect", f"{self.host}:{self.port}",
            "-groups", "X25519MLKEM768",
            "-servername", sni if sni else self.host,
            "-brief",
            "-no_ssl3", "-no_tls1", "-no_tls1_1", "-no_tls1_2"
        ]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
        except subprocess.TimeoutExpired:
            return ProbeResult(
                error_reason="timeout",
                downgrade_detected=False
            )
        except FileNotFoundError:
            return ProbeResult(
                error_reason="openssl_not_available"
            )
        output = proc.stdout + proc.stderr
        # Check for errors in output
        if "connect:" in output.lower() and "errno" in output.lower():
            return ProbeResult(
                error_reason="connection_failed"
            )
        if "no protocols available" in output.lower() or "sslv3 alert handshake failure" in output.lower():
            return ProbeResult(
                error_reason="handshake_failure"
            )
        # Parse the output for group negotiation
        return self._parse_openssl_output(output)
    def _parse_openssl_output(self, output: str) -> ProbeResult:
            """Parse OpenSSL s_client output for hybrid group info."""
            result = ProbeResult()
            output_lower = output.lower()
            # Check for connection errors (connection refused, connection failed, etc.)
            if "connect:" in output_lower and (("errno" in output_lower or "refused" in output_lower or "failed" in output_lower)):
                result.error_reason = "connection_failed"
                return result
            # Check for handshake failure
            if "sslv3 alert handshake failure" in output_lower:
                result.error_reason = "handshake_failure"
                return result
            # Check for TLS 1.2 or older - hybrid groups only in TLS 1.3+
            if "protocol: tls 1.2" in output_lower or "protocol: tls 1.1" in output_lower or "protocol: tls 1.0" in output_lower:
                result.downgrade_detected = False
                result.error_reason = "unsupported_protocol"
                return result
            # Check for unsupported protocol
            if "no protocols available" in output_lower:
                result.error_reason = "unsupported_protocol"
                return result
            # Look for the negotiated group - check for exact hybrid group first (case insensitive)
            if "x25519mlkem768" in output_lower:
                result.group_codepoint = HYBRID_GROUP_CODEPOINT
                result.mlkem_shared_first = True  # RFC 10024: ML-KEM shared secret first
                result.downgrade_detected = False
            elif "supported groups" in output_lower or "group:" in output_lower:
                # TLS 1.3 negotiated but not the hybrid group (already checked above)
                # Check if classical X25519 is offered
                if "x25519" in output_lower:
                    if "X25519" in output:
                        # Exact-case negotiated key exchange showing classical X25519 - downgrade
                        result.group_codepoint = 29
                        result.mlkem_shared_first = False
                        result.downgrade_detected = True
                        result.error_reason = "downgrade-to-classical"
                    else:
                        # Classical only in a supported-groups listing - hybrid group not offered
                        result.downgrade_detected = True
                        result.error_reason = "hybrid_group_not_offered"
                else:
                    # Supported groups listed but no X25519 or hybrid group detected
                    result.downgrade_detected = True
                    result.error_reason = "hybrid_group_not_offered"
            elif "x25519" in output_lower:
                # Check if it's a different ML-KEM hybrid group (e.g., MLKEM512, MLKEM1024)
                if "mlkem" in output_lower:
                    # Hybrid group present but not X25519MLKEM768
                    result.downgrade_detected = True
                    result.error_reason = "hybrid_group_not_offered"
                else:
                    # Classical X25519 only - downgrade detected
                    result.group_codepoint = 29  # X25519 codepoint per RFC 7919
                    result.mlkem_shared_first = False
                    result.downgrade_detected = True
                    result.error_reason = "downgrade-to-classical"
            elif "handshake" in output_lower:
                # TLS handshake occurred but no group info detected - hybrid group not offered
                result.downgrade_detected = True
                result.error_reason = "hybrid_group_not_offered"
            else:
                # Could not determine - return result indicating manual probe needed
                result.error_reason = "manual_probe_not_implemented: Use OpenSSL s_client for probing"
            return result
    def _probe_manual(self, sni: Optional[str] = None) -> ProbeResult:
        """Manual TLS 1.3 ClientHello parsing fallback."""
        # First build the ClientHello - _build_client_hello raises NotImplementedError
        # which is caught and returns manual_probe_not_implemented
        try:
            client_hello = self._build_client_hello(sni)
        except NotImplementedError:
            return ProbeResult(
                error_reason="manual_probe_not_implemented: Use OpenSSL s_client for probing"
            )

        # Connect and send
        try:
            result = socket.create_connection((self.host, self.port), timeout=self.timeout)
            if isinstance(result, tuple):
                sock, addr = result
            else:
                sock = result
        except socket.timeout:
            return ProbeResult(error_reason="timeout")
        except ConnectionRefusedError:
            return ProbeResult(error_reason="connection_refused")
        except Exception as e:
            return ProbeResult(error_reason=f"probe_error: {str(e)}")
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        # Disable older TLS versions
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        # For custom ClientHello, we'd need to use lower-level APIs
        # This is a simplified fallback
        try:
            sock.send(client_hello)
        except Exception:
            sock.close()
            return ProbeResult(error_reason="probe_error: send_failed")
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        # Disable older TLS versions
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
        # For custom ClientHello, we'd need to use lower-level APIs
        # This is a simplified fallback
        try:
            sock.send(client_hello)
        except Exception:
            sock.close()
            return ProbeResult(error_reason="probe_error: send_failed")
        # Read ServerHello
        try:
            response = sock.recv(4096)
        except Exception:
            sock.close()
            return ProbeResult(error_reason="probe_error: recv_failed")
        sock.close()
        return self._parse_server_hello(response)
    def _build_client_hello(self, sni: Optional[str] = None) -> bytes:
        """Build a minimal TLS 1.3 ClientHello with hybrid group support."""
        # This is a simplified version - in practice we'd use a proper TLS library
        # For the probe, we mainly use OpenSSL
        raise NotImplementedError("Use OpenSSL s_client for probing")
    def _parse_server_hello(self, data: bytes) -> ProbeResult:
        """Parse ServerHello for group negotiation."""
        result = ProbeResult()
        # Minimal parsing - look for supported_groups extension in ServerHello
        # TLS 1.3 handshake format parsing would go here
        # For now, rely on OpenSSL output
        if len(data) > 0:
            data_lower = data.lower()
            # Very basic heuristic - check for exact X25519MLKEM768 first
            if b"x25519mlkem768" in data_lower:
                result.group_codepoint = HYBRID_GROUP_CODEPOINT
                result.mlkem_shared_first = True
            elif b"mlkem" in data_lower:
                # Check if it's a different ML-KEM variant (512, 1024)
                if b"mlkem512" in data_lower or b"mlkem1024" in data_lower:
                    # Hybrid group present but not X25519MLKEM768
                    result.downgrade_detected = True
                    result.error_reason = "hybrid_group_not_offered"
                else:
                    # Bare "mlkem" or "mlkem768" - treat as X25519MLKEM768
                    result.group_codepoint = HYBRID_GROUP_CODEPOINT
                    result.mlkem_shared_first = True
            elif b"x25519" in data_lower:
                # Classical X25519 only - downgrade detected
                result.group_codepoint = 29
                result.downgrade_detected = True
                result.error_reason = "downgrade-to-classical"
            else:
                result.error_reason = "group_detection_failed"
        else:
            result.error_reason = "empty_response"
        return result
    @staticmethod
    def get_shared_secret_layout() -> Dict[str, Any]:
        """
        Return the RFC 10024 shared secret layout for X25519MLKEM768.
        Returns:
            Dictionary describing the concatenation order and byte lengths
        """
        return {
            "group_name": HYBRID_GROUP_NAME,
            "codepoint": HYBRID_GROUP_CODEPOINT,
            "client_key_exchange_bytes": CLIENT_KEY_EXCHANGE_LEN,
            "server_key_exchange_bytes": SERVER_KEY_EXCHANGE_LEN,
            "shared_secret_bytes": SHARED_SECRET_LEN,
            "concatenation_order": "mlkem_shared_secret || x25519_shared_secret",
            "mlkem_shared_first": True,
            "mlkem_shared_secret_bytes": 32,
            "x25519_shared_secret_bytes": 32,
            "mlkem_encapsulation_bytes": 1184,
            "mlkem_ciphertext_bytes": 1088,
            "x25519_ephemeral_bytes": 32,
            "hkdf_hash": "SHA-384",
            "reference": "RFC 10024 Section 4.1, 4.2, 4.3, 7.1"
        }
def main() -> int:
    """Command-line entry point for the hybrid group probe."""
    import argparse
    parser = argparse.ArgumentParser(
        description="Probe TLS endpoint for X25519MLKEM768 hybrid group support (RFC 10024)"
    )
    parser.add_argument("host", help="Target hostname or IP")
    parser.add_argument("-p", "--port", type=int, default=443, help="Target port (default: 443)")
    parser.add_argument("--sni", help="SNI value to send")
    parser.add_argument("--timeout", type=float, default=10.0, help="Connection timeout (default: 10.0)")
    parser.add_argument("--layout", action="store_true", help="Print RFC 10024 shared secret layout and exit")
    args = parser.parse_args()
    if args.layout:
        layout = HybridGroupProbe.get_shared_secret_layout()
        print(json.dumps(layout, indent=2))
        return 0
    probe = HybridGroupProbe(args.host, args.port, args.timeout)
    result = probe.probe(args.sni)
    print(result.to_json())
    # Exit with non-zero if hybrid group not offered or downgrade detected
    if result.error_reason in ("hybrid_group_not_offered", "downgrade-to-classical") or result.downgrade_detected:
        return 1
    if result.error_reason and result.error_reason not in ("timeout",):
        return 2
    return 0
if __name__ == "__main__":
    sys.exit(main())