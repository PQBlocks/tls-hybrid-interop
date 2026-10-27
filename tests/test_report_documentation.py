"""Verification of package metadata and group specification."""
from pqblocks_tls_interop.verifier.probe import HYBRID_GROUP_NAME, HYBRID_GROUP_CODEPOINT


def test_package_metadata_and_group_specification():
    """Verify package exposes expected hybrid group specifications."""
    assert HYBRID_GROUP_NAME == "X25519MLKEM768"
    assert HYBRID_GROUP_CODEPOINT == 4588

