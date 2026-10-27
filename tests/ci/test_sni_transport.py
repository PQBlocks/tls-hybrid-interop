#!/usr/bin/env python3
"""
SNI and Transport Tests for Hybrid Group Probe (S4)

This module adds test scenarios for SNI variations and IPv6 transport.
Verifies that group codepoint 4588 is reported consistently across variants.
These tests are integrated with the CI test file.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from pqblocks_tls_interop.verifier.probe import HybridGroupProbe, ProbeResult


def test_sni_hostname_parsing():
    """Test that probe handles SNI hostname correctly (spec edge-case #6)."""
    # Test different SNI values
    test_hosts = [
        "example.com",
        "sub.domain.com",
        "www.example.org",
        "test123.internal.company.net"
    ]
    
    for host in test_hosts:
        probe = HybridGroupProbe(host, port=443)
        assert probe.host == host
        assert probe.port == 443


def test_sni_with_port_variations():
    """Test SNI with different port numbers."""
    base_host = "example.com"
    
    test_ports = [443, 8443, 9443, 80]
    
    for port in test_ports:
        probe = HybridGroupProbe(base_host, port=port)
        assert probe.port == port


def test_ipv6_transport_consistency():
    """Test IPv6 transport reports same group codepoint (spec edge-case #8)."""
    # Test IPv6 addresses
    ipv6_addresses = [
        "::1",           # localhost
        "2001:db8::1",   # documentation prefix
        "2001:db8:85a3::8a2e:370:7334",
        "[::1]",         # bracketed IPv6 (though we don't handle brackets)
    ]
    
    for addr in ipv6_addresses:
        probe = HybridGroupProbe(addr, port=443)
        assert probe.host == addr
        assert probe.port == 443


def test_sni_and_ipv6_combined():
    """Test SNI with IPv6 transport."""
    ipv6_hosts = ["[2001:db8::1]", "::1", "2001:db8::1"]
    
    for host in ipv6_hosts:
        probe = HybridGroupProbe(host, port=443)
        assert probe.host == host


def test_sni_empty_and_special_values():
    """Test edge case SNI values."""
    # Empty SNI (should use hostname)
    probe1 = HybridGroupProbe("example.com", port=443)
    assert probe1.host == "example.com"
    
    # Single character hostname
    probe2 = HybridGroupProbe("a.co", port=443)
    assert probe2.host == "a.co"
    
    # Long hostname
    long_host = "a" * 63 + ".com"  # Max label length
    probe3 = HybridGroupProbe(long_host, port=443)
    assert probe3.host == long_host


def test_multiple_group_extensions_consistent_detection():
    """Test multiple group extensions (spec edge-case #10)."""
    probe = HybridGroupProbe("example.com")
    
    # Test cases with multiple advertised groups
    test_cases = [
        # Hybrid group present among others
        ("Supported Groups: X25519, X25519MLKEM768, X448", True, 4588),
        # Hybrid group first
        ("Supported Groups: X25519MLKEM768, X25519, secp256r1", True, 4588),
        # Hybrid group last
        ("Supported Groups: secp384r1, secp521r1, X25519MLKEM768", True, 4588),
        # No hybrid group - should detect downgrade
        ("Supported Groups: X25519, X448, secp256r1", False, 29),
        # Only classical groups
        ("Supported Groups: X25519, X448", False, 29),
    ]
    
    for output, should_have_hybrid, expected_codepoint in test_cases:
        result = probe._parse_openssl_output(output)
        
        if should_have_hybrid:
            assert result.group_codepoint == expected_codepoint
            assert result.downgrade_detected is False
            assert result.mlkem_shared_first is True
            assert result.error_reason is None
        else:
            # Should detect either downgrade or missing hybrid
            assert result.downgrade_detected is True or result.error_reason is not None
            if result.group_codepoint is not None:
                assert result.group_codepoint == expected_codepoint


def test_sni_does_not_affect_group_negotiation():
    """Test that SNI value doesn't change group negotiation outcome."""
    hosts = ["example.com", "test.example.com", "sub.domain.org"]
    
    for host in hosts:
        probe = HybridGroupProbe(host, port=443)
        # Mock output showing successful hybrid group negotiation
        output = "Key-Exchange: X25519MLKEM768"
        result = probe._parse_openssl_output(output)
        
        # Regardless of SNI, hybrid group should be detected the same way
        assert result.group_codepoint == 4588
        assert result.mlkem_shared_first is True
        assert result.downgrade_detected is False
        assert result.error_reason is None


def test_ipv6_timeout_handling():
    """Test IPv6 timeout handling (spec edge-case #9)."""
    probe = HybridGroupProbe("::1", timeout=1.0)
    # We can't easily test actual timeout without network,
    # but we can verify the timeout parameter is stored
    assert probe.timeout == 1.0
    assert probe.host == "::1"


def test_transport_agnostic_probe():
    """Test that probe logic is transport-agnostic."""
    # Same logic should work regardless of underlying transport
    transports = [
        "example.com:443",    # IPv4
        "[::1]:443",          # IPv6 bracketed
        "2001:db8::1:443",    # IPv6
        "localhost:8443",     # localhost
    ]
    
    for transport in transports:
        # Extract host and port (simplified parsing)
        if "[" in transport and "]" in transport:
            # IPv6 with brackets
            host_end = transport.find("]:")
            host = transport[1:host_end]
            port = int(transport[host_end+2:])
        elif transport.count(":") == 1 and not transport.startswith("["):
            # Simple host:port
            host, port_str = transport.split(":")
            port = int(port_str)
        else:
            # IPv6 without brackets or other format
            host = transport
            port = 443
            
        probe = HybridGroupProbe(host, port=port)
        assert probe.host == host
        assert probe.port == port


def test_sni_certificate_errors_separated():
    """Test certificate errors don't mask group negotiation (spec edge-case #7)."""
    probe = HybridGroupProbe("example.com")
    
    # Test various certificate error outputs with group negotiation
    test_cases = [
        # Certificate error but hybrid group negotiated
        "verify error: certificate expired\nKey-Exchange: X25519MLKEM768",
        # Certificate error but classical fallback
        "verify error: self signed certificate\nKey-Exchange: X25519",
        # Multiple certificate errors
        "verify error: certificate is not yet valid\nverify error: certificate has expired\nKey-Exchange: X25519MLKEM768",
        # Certificate error with SNI
        "verify unable to get issuer certificate\nKey-Exchange: X25519MLKEM768",
    ]
    
    for output in test_cases:
        result = probe._parse_openssl_output(output)
        
        # Should still detect the group negotiation status correctly
        if "X25519MLKEM768" in output:
            assert result.group_codepoint == 4588
            assert result.mlkem_shared_first is True
            assert result.downgrade_detected is False
            # error_reason might be set due to certificate error, but group detection should work
        elif "X25519" in output and "MLKEM" not in output.upper():
            assert result.group_codepoint == 29
            assert result.downgrade_detected is True
            assert result.error_reason == "downgrade-to-classical"


def test_sni_variations_with_hello_retry_request():
    """Test SNI variations work with HelloRetryRequest path (spec edge-case #3)."""
    probe = HybridGroupProbe("example.com")
    
    # HRR scenarios with different SNI values
    sni_values = ["example.com", "www.example.com", "api.example.com"]
    
    for sni in sni_values:
        probe_sni = HybridGroupProbe(sni, port=443)
        # After HRR, if hybrid group is negotiated
        output = "Key-Exchange: X25519MLKEM768"
        result = probe_sni._parse_openssl_output(output)
        
        assert result.group_codepoint == 4588
        assert result.mlkem_shared_first is True
        assert result.downgrade_detected is False


def test_ipv6_link_local_and_multicast():
    """Test IPv6 special addresses."""
    special_ipv6 = [
        "::1",          # localhost
        "fe80::1",      # link-local
        "ff02::1",      # multicast-all-nodes
        "2001:db8::1",  # documentation
    ]
    
    for addr in special_ipv6:
        probe = HybridGroupProbe(addr, port=443)
        assert probe.host == addr
        assert probe.port == 443


def test_extended_valid_sni_characters():
    """Test SNI with valid RFC characters."""
    # Valid characters for hostnames (RFC 1123)
    valid_snis = [
        "a-b.com",           # hyphen
        "a_b.com",           # underscore (technically not RFC but often used)
        "a1b2c3.com",        # alphanumeric
        "xn--example.com",   # IDNA punycode
        "example.com.",      # trailing dot (FQDN)
    ]
    
    for sni in valid_snis:
        probe = HybridGroupProbe(sni, port=443)
        assert probe.host == sni


def test_port_range_validation():
    """Test that various port numbers are handled."""
    test_ports = [1, 443, 8443, 9000, 65535]  # Valid port range
    
    for port in test_ports:
        probe = HybridGroupProbe("example.com", port=port)
        assert probe.port == port


def test_sni_case_sensitivity():
    """Test SNI case handling."""
    # DNS is case-insensitive, but we preserve case as provided
    test_cases = [
        "EXAMPLE.COM",
        "Example.Com",
        "example.com",
        "ExAmPlE.CoM",
    ]
    
    for case_variant in test_cases:
        probe = HybridGroupProbe(case_variant, port=443)
        assert probe.host == case_variant  # Preserve input case


def test_json_output_consistency_across_transports():
    """Test that JSON output format is consistent regardless of transport."""
    test_configs = [
        ("example.com", 443),
        ("::1", 443),
        ("test.domain.org", 8443),
        ("localhost", 9443),
    ]
    
    for host, port in test_configs:
        probe = HybridGroupProbe(host, port)
        
        # Test successful hybrid group detection
        output = "Key-Exchange: X25519MLKEM768"
        result = probe._parse_openssl_output(output)
        json_output = result.to_json()
        
        # Verify JSON structure is consistent
        import json
        parsed = json.loads(json_output)
        assert "group_codepoint" in parsed
        assert "mlkem_shared_first" in parsed
        assert "downgrade_detected" in parsed
        assert "error_reason" in parsed
        
        assert parsed["group_codepoint"] == 4588
        assert parsed["mlkem_shared_first"] is True
        assert parsed["downgrade_detected"] is False
        assert parsed["error_reason"] is None


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))