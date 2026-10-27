"""
Test that executes the module as a script to cover line 335.
"""

import subprocess
import sys


def test_main_guard_execution():
    """Execute the probe module as a script to cover line 335: sys.exit(main())."""
    import os
    from pathlib import Path
    env = os.environ.copy()
    src_dir = str(Path(__file__).resolve().parent.parent / "src")
    if os.path.isdir(src_dir):
        env['PYTHONPATH'] = f"{src_dir}:{env.get('PYTHONPATH', '')}"
    # Run the module with --layout flag to trigger successful execution
    result = subprocess.run(
        [sys.executable, '-m', 'pqblocks_tls_interop.verifier.probe', '--layout', 'example.com'],
        capture_output=True,
        text=True,
        timeout=10,
        env=env,
    )
    
    # Should succeed with exit code 0 and output JSON
    assert result.returncode == 0
    assert '"group_name": "X25519MLKEM768"' in result.stdout
    assert '"codepoint": 4588' in result.stdout
    assert result.stdout.strip().startswith('{')