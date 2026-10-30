"""Windows portability: text I/O never relies on the locale encoding (cp1252 on Windows),
and terminal output never crashes when redirected to a stream that can't encode it."""
import io
import re
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"


def test_no_text_io_without_explicit_encoding():
    bad = []
    for f in SRC.rglob("*.py"):
        for n, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
            # (a urllib opener's .open() returns bytes: there is no encoding to give)
            if re.search(r"\.(read_text|write_text)\(|\bopen\(|fdopen\(", line) \
                    and "encoding=" not in line and "os.open(" not in line and "_bytes" not in line \
                    and "opener.open(" not in line \
                    and not re.search(r"""["'][rwa]b\+?["']""", line):        # binary mode
                bad.append(f"{f.relative_to(SRC)}:{n}: {line.strip()}")
    assert not bad, "text I/O without encoding= (breaks on Windows):\n" + "\n".join(bad)


def test_terminal_output_survives_a_cp1252_stream(monkeypatch):
    from cloudtools import cli
    raw = io.BytesIO()
    stream = io.TextIOWrapper(raw, encoding="cp1252")        # strict, like a Windows redirect
    monkeypatch.setattr(sys, "stdout", stream)
    cli._safe_stdout()
    print("internet → admin · key …WXYZ")
    sys.stdout.flush()
    assert raw.getvalue()                                    # wrote something, no exception
