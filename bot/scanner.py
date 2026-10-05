"""
Luraph header-banner scanner.
"""

from __future__ import annotations

import re
from pathlib import Path

SCAN_BYTES = 8192

BANNER_RE = re.compile(
    r"""This\s+file\s+was\s+protected\s+using\s+
        Luraph\s+Obfuscator\s+
        v(1[45](?:\.\d+)*)                   # 14, 14.0..14.9, 15, 15.0..15.99
        (?:\s*\[\s*([^\]\s]+)\s*\])?         # optional [https://lura.ph/]
    """,
    re.IGNORECASE | re.VERBOSE,
)


def _decode_head(path: Path, n: int = SCAN_BYTES) -> str:
    with path.open("rb") as f:
        raw = f.read(n)
    for enc in ("utf-8-sig", "utf-8", "latin-1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("latin-1", errors="replace")


def _engine_for(version: str) -> str | None:
    v = version.strip().lstrip("vV")

    if v in ("14.7", "14.8", "14.9"):
        return v

    parts = v.split(".")
    major = parts[0]

    if major == "14":
        return "auto"

    if major == "15":
        return "luraph_v15"

    return None


def scan(path: Path) -> dict:
    try:
        head = _decode_head(path)
    except OSError as e:
        return {
            "found": False,
            "version": None,
            "major": None,
            "minor": None,
            "engine": None,
            "banner": None,
            "url": None,
            "error": str(e),
        }

    m = BANNER_RE.search(head)
    if not m:
        return {
            "found": False,
            "version": None,
            "major": None,
            "minor": None,
            "engine": None,
            "banner": None,
            "url": None,
        }

    version = m.group(1).lstrip("vV")
    url = m.group(2)

    parts = version.split(".")
    major = parts[0]
    try:
        minor = int(parts[1]) if len(parts) > 1 else None
    except ValueError:
        minor = None

    line_start = head.rfind("\n", 0, m.start()) + 1
    line_end = head.find("\n", m.end())
    if line_end == -1:
        line_end = len(head)
    line = head[line_start:line_end].strip()

    return {
        "found": True,
        "version": version,
        "major": major,
        "minor": minor,
        "engine": _engine_for(version),
        "banner": line,
        "url": url,
    }


def pretty_version(path: Path) -> str:
    info = scan(path)
    if not info["found"]:
        return "no Luraph banner"
    return f"Luraph v{info['version']}"


if __name__ == "__main__":
    import sys
    for p in sys.argv[1:]:
        print(p, "->", scan(Path(p)))
