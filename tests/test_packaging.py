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


def test_serve_extra_cannot_resolve_a_vulnerable_starlette():
    """CT-18: `fastapi>=0.115` alone let starlette 0.38.6 stay installed (pip-audit
    2026-10-30: CVE-2024-47874, CVE-2025-54121 and five later advisories, fixed by 1.3.1)."""
    import re
    import tomllib
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    serve = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))[
        "project"]["optional-dependencies"]["serve"]
    floor = [re.match(r"starlette>=([\d.]+)", d) for d in serve]
    got = [tuple(int(x) for x in m.group(1).split(".")) for m in floor if m]
    assert got and got[0] >= (1, 3, 1), serve


def test_ci_runs_only_pinned_code():
    """CT-22: actions were pinned by tag (movable) and the gitleaks binary was piped to tar
    with no checksum."""
    import re
    from pathlib import Path
    ci = (Path(__file__).resolve().parents[1] / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    uses = re.findall(r"uses:\s*(\S+)", ci)
    assert uses and all(re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", u) for u in uses), uses
    assert re.search(r"sha256sum -c", ci) and "| tar" not in ci, "verify the download before unpacking"
