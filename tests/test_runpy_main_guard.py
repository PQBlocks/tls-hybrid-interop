"""
Test to cover line 335 by running the module as a script using runpy.
"""

import sys
from unittest.mock import patch

# Ensure we can import the module
sys.path.insert(0, '../src')

import runpy


def test_main_guard_by_running_module():
    """Cover line 335: sys.exit(main()) by running the module as a script."""
    # Save original sys.argv
    original_argv = sys.argv.copy()

    try:
        # Set sys.argv to simulate --layout flag
        sys.argv = ['probe.py', '--layout', 'dummyhost']

        # Mock sys.exit to prevent the test from exiting and to capture the call
        with patch('sys.exit') as mock_exit:
            # Run the module as if it were the main module
            runpy.run_module('pqblocks_tls_interop.verifier.probe', run_name='__main__')

            # Verify sys.exit was called (this covers line 335)
            mock_exit.assert_called_once()
    finally:
        # Restore original sys.argv
        sys.argv = original_argv