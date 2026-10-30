"""The built wheel carries every data file the code reads. v0.1.1 shipped without
security/data/*.json, so an installed copy failed os-end-of-life and offline CVE
matching (found 2026-10-29, after the live lab)."""
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_wheel_contains_every_package_data_file(tmp_path):
    r = subprocess.run([sys.executable, "-m", "pip", "wheel", str(ROOT), "--no-deps",
                        "--no-build-isolation", "-q", "-w", str(tmp_path)],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    wheel, = tmp_path.glob("cloudtools-*.whl")
    names = set(zipfile.ZipFile(wheel).namelist())
    src = ROOT / "src"
    want = {p.relative_to(src).as_posix() for p in src.rglob("*.json")
            if "egg-info" not in p.as_posix()}
    assert want and want <= names, sorted(want - names)
