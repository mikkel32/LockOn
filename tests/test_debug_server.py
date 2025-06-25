import subprocess
import sys
from pathlib import Path


def test_debug_server_exits_gracefully_without_debugpy():
    result = subprocess.run(
        [sys.executable, str(Path('debug_server.py'))],
        text=True,
        capture_output=True,
    )
    assert result.returncode == 0
    assert "debugpy is required" in result.stdout
