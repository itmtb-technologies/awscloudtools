"""Fail if a file that would be published names a real account or a local machine.

Public = every tracked file except `docs/internal/` (planning notes). `tests/` is
checked for paths and markers but not account ids (its fixtures use deliberate fake ones). Checked: 12-digit AWS account ids other than the
documentation examples, home-directory paths, and any extra marker listed one per line in
`docs/internal/markers.txt` (internal on purpose: the list itself names the private things).

    python tools/check_public.py        # exit 1 and list each hit
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXCLUDED = ("docs/internal/",)
FAKE_IDS_OK = "tests/"
EXAMPLE_ACCOUNTS = {"123456789012", "000000000000", "111111111111", "999999999999"}
PATTERNS = [re.compile(r"(?<![\d.])\d{12}(?![\d.])"), re.compile(r"/Users/[A-Za-z]|/home/[a-z]+/|~/z1\b|~/\.claude")]


def public_files() -> list[str]:
    out = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True)
    # Itself excluded: its own patterns spell what they look for (a self-hit failed CI).
    return [f for f in out.stdout.splitlines()
            if not f.startswith(EXCLUDED) and f not in ("LICENSE", "tools/check_public.py")]


def hits(markers: list[str]) -> list[str]:
    found = []
    for f in public_files():
        try:
            text = (ROOT / f).read_text(encoding="utf-8")
        except (UnicodeDecodeError, FileNotFoundError):
            continue
        for n, line in enumerate(text.splitlines(), 1):
            ids = [] if f.startswith(FAKE_IDS_OK) else [
                m for m in PATTERNS[0].findall(line) if m not in EXAMPLE_ACCOUNTS]
            if ids or PATTERNS[1].search(line) or any(m.lower() in line.lower() for m in markers):
                found.append(f"{f}:{n}: {line.strip()[:120]}")
    return found


def main() -> int:
    mfile = ROOT / "docs/internal/markers.txt"
    markers = [m.strip() for m in mfile.read_text(encoding="utf-8").splitlines()
               if m.strip() and not m.startswith("#")] if mfile.exists() else []
    found = hits(markers)
    for h in found:
        print(h)
    print(f"{len(found)} internal reference(s) in public files" if found else "public files are clean")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
