"""Public files name no real account, local path or internal marker (tools/check_public.py)."""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_public_files_are_clean():
    r = subprocess.run([sys.executable, str(ROOT / "tools/check_public.py")], cwd=ROOT,
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stdout
