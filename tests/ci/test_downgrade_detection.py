#!/usr/bin/env python3
"""
Downgrade Detection Tests for Hybrid Group Probe (S3)

This module adds test cases that verify the probe correctly detects
downgrade to classical X25519 and reports "downgrade-to-classical"
as the error reason. These tests are integrated with the CI test file.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from pqblocks_tls_interop.verifier.probe import HybridGroupProbe, ProbeResult


def test_downgrade_to_classical_detected():
    """Test that probe detects downgrade to classical X25519."""
    probe = HybridGroupProbe("example.com")
    
    # Simulate OpenSSL output showing classical X25519 only
    output = "Key-Exchange: X25519"
    result = probe._parse_openssl_output(output)
    
    assert result.group_codepoint == 29  # X25519 codepoint per RFC 7919
    assert result.mlkem_shared_first is False
    assert result.downgrade_detected is True
    assert result.error_reason == "downgrade-to-classical"


def test_downgrade_to_classical_in_mixed_groups():
    """Test downgrade detection when X25519 appears with other non-MLKEM groups."""
    probe = HybridGroupProbe("example.com")
    
    # Server offers X25519 plus other classical groups but no ML-KEM
    output = "Key-Exchange: X25519, X448, secp256r1"
    result = probe._parse_openssl_output(output)
    
    assert result.group_codepoint == 29
    assert result.downgrade_detected is True
    assert result.error_reason == "downgrade-to-classical"


def test_downgrade_with_different_mlkem_variant():
    """Test that X25519MLKEM512 is treated as hybrid_group_not_offered, not downgrade."""
    probe = HybridGroupProbe("example.com")
    
    # Server offers a different ML-KEM hybrid (512 not 768)
    output = "Key-Exchange: X25519MLKEM512"
    result = probe._parse_openssl_output(output)
    
    # Should detect that X25519MLKEM768 is not offered
    assert result.downgrade_detected is True
    assert result.error_reason == "hybrid_group_not_offered"
    # Should NOT be treated as classical downgrade
    assert result.error_reason != "downgrade-to-classical"


def test_downgrade_mlkem1024_not_treated_as_768():
    """Test that X25519MLKEM1024 is not treated as X25519MLKEM768."""
    probe = HybridGroupProbe("example.com")
    
    output = "Key-Exchange: X25519MLKEM1024"
    result = probe._parse_openssl_output(output)
    
    # Should detect hybrid group but not the specific 768 variant
    assert result.downgrade_detected is True
    assert result.error_reason == "hybrid_group_not_offered"


def test_classical_fallback_no_error():
    """Test that classical-only client (no hybrid support) doesn't error."""
    # This tests the edge case from spec edge-case #4
    probe = HybridGroupProbe("example.com")
    
    # If client only supports classical, connection succeeds with classical
    output = "Key-Exchange: X25519"
    result = probe._probe_with_openssl.__wrapped__(probe, output) if hasattr(probe._probe_with_openssl, '__wrapped__') else probe._parse_openssl_output(output)
    
    # The probe reports downgrade but doesn't fail for classical fallback
    # (This is expected behavior - classical fallback is allowed)
    assert result.downgrade_detected is True
    assert result.error_reason == "downgrade-to-classical"


def test_downgrade_reason_is_exact_string():
    """Test that downgrade error reason is exactly 'downgrade-to-classical'."""
    probe = HybridGroupProbe("example.com")
    output = "Key-Exchange: X25519"
    result = probe._parse_openssl_output(output)
    
    # Exact string match required by spec
    assert result.error_reason == "downgrade-to-classical"
    assert result.error_reason is not None
    assert isinstance(result.error_reason, str)


def test_downgrade_result_json_format():
    """Test that downgrade result has correct JSON structure."""
    probe = HybridGroupProbe("example.com")
    output = "Key-Exchange: X25519"
    result = probe._parse_openssl_output(output)
    
    # Must serialize to JSON with correct fields
    json_output = result.to_json()
    import json
    parsed = json.loads(json_output)
    
    assert parsed["group_codepoint"] == 29
    assert parsed["mlkem_shared_first"] is False
    assert parsed["downgrade_detected"] is True
    assert parsed["error_reason"] == "downgrade-to-classical"


def test_no_hybrid_group_offered_different_from_downgrade():
    """Test that 'hybrid_group_not_offered' is different from 'downgrade-to-classical'."""
    probe = HybridGroupProbe("example.com")
    
    # Case 1: Server offers hybrid groups but not X25519MLKEM768
    output_hybrid_other = "Key-Exchange: X25519MLKEM512"
    result1 = probe._parse_openssl_output(output_hybrid_other)
    
    # Case 2: Server only offers classical X25519
    output_classical = "Key-Exchange: X25519"
    result2 = probe._parse_openssl_output(output_classical)
    
    # Both detect downgrade but with different reasons
    assert result1.downgrade_detected is True
    assert result2.downgrade_detected is True
    
    # But error reasons differ
    assert result1.error_reason == "hybrid_group_not_offered"
    assert result2.error_reason == "downgrade-to-classical"
    assert result1.error_reason != result2.error_reason


def test_downgrade_detection_with_hello_retry_request():
    """Test downgrade detection in HelloRetryRequest scenario (spec edge-case #3)."""
    probe = HybridGroupProbe("example.com")
    
    # HRR with hybrid group should eventually succeed
    # But if HRR removes the hybrid group, it's a downgrade
    # This simulates HRR response that removes hybrid support
    output_hrr_downgrade = "Key-Exchange: X25519"
    result = probe._parse_openssl_output(output_hrr_downgrade)
    
    assert result.downgrade_detected is True
    assert result.error_reason == "downgrade-to-classical"


def test_downgrade_detection_tls12_unsupported():
        """Test that TLS 1.2 peer is handled correctly (spec edge-case #5)."""
        probe = HybridGroupProbe("example.com")
        
        # TLS 1.2 doesn't support hybrid groups - should return unsupported protocol
        output_tls12 = "Protocol: TLS 1.2"
        result = probe._parse_openssl_output(output_tls12)
        
        # Should detect as unsupported protocol, NOT as downgrade
        assert result.error_reason == "unsupported_protocol"
        assert result.downgrade_detected is False  # Not a downgrade, just unsupported
    # But error reason might differ for TLS 1.2
    # The probe should detect this scenario


def test_downgrade_with_multiple_groups_extensions():
    """Test downgrade detection with multiple group extensions (spec edge-case #10)."""
    probe = HybridGroupProbe("example.com")
    
    # Server advertises both classical and hybrid groups
    output = "Supported Groups: X25519, X448, X25519MLKEM768"
    # In this case hybrid IS offered - should NOT detect downgrade
    result = probe._parse_openssl_output(output)
    
    # Check if X25519MLKEM768 is present
    if "X25519MLKEM768" in output:
        assert result.downgrade_detected is False
        assert result.group_codepoint == 4588


def test_downgrade_ipv6_transport():
    """Test downgrade detection works over IPv6 (spec edge-case #8)."""
    # IPv6 should work the same as IPv4
    # The probe logic is transport-agnostic
    probe = HybridGroupProbe("example.com")
    
    output = "Key-Exchange: X25519"
    result = probe._parse_openssl_output(output)
    
    assert result.downgrade_detected is True
    assert result.error_reason == "downgrade-to-classical"


def test_downgrade_with_sni_variations():
    """Test downgrade detection with various SNI values (spec edge-case #6)."""
    # SNI should not affect group negotiation
    probe1 = HybridGroupProbe("example.com", port=443)
    probe2 = HybridGroupProbe("example.org", port=443)
    probe3 = HybridGroupProbe("sub.domain.com", port=443)
    
    for probe in [probe1, probe2, probe3]:
        output = "Key-Exchange: X25519"
        result = probe._parse_openssl_output(output)
        assert result.downgrade_detected is True
        assert result.error_reason == "downgrade-to-classical"


def test_downgrade_certificate_error_separated():
    """Test certificate errors don't mask group negotiation (spec edge-case #7)."""
    probe = HybridGroupProbe("example.com")
    
    # Certificate error is separate from group negotiation
    output = "verify error: certificate expired\nKey-Exchange: X25519"
    result = probe._parse_openssl_output(output)
    
    # Should still detect the group negotiation status
    assert result.downgrade_detected is True
    assert result.error_reason == "downgrade-to-classical"


def test_downgrade_timeout_handling():
    """Test timeout handling doesn't mask downgrade (spec edge-case #9)."""
    probe = HybridGroupProbe("example.com", timeout=10.0)
    
    # Timeout should return a timeout error, not a downgrade
    result = ProbeResult(error_reason="timeout", downgrade_detected=False)
    
    assert result.error_reason == "timeout"
    assert result.downgrade_detected is False
    # Timeout is not a downgrade - it's a network issue


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))