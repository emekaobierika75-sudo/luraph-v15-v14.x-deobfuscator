
"""
Luraph header-banner scanner.

The banner sits in the first comment line of a Luraph-protected file:

    -- This file was protected using Luraph Obfuscator v14.0 [https://lura.ph/]
    -- This file was protected using Luraph Obfuscator v14.7 [https://lura.ph/]
    -- This file was protected using Luraph Obfuscator v14.9 [https://lura.ph/]
    -- This file was protected using Luraph Obfuscator v15   [https://lura.ph/]
    -- This file was protected using Luraph Obfuscator v15.1 [https://lura.ph/]

Covers every Luraph version from v14.0 up to and including v15.x.

Tolerant of:
    * any case (upper / lower)
    * Lua comment prefix `--` or none at all
    * missing trailing bracket / URL
    * extra whitespace and newlines inside the phrase
    * BOM, utf-8, latin-1 input
"""

from __future__ import annotations

import re
from pathlib import Path

SCAN_BYTES = 8192

# 14.0 - 15.x  (any minor version at or after 14.0 and before 16)
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
    """
    Map a banner version to what the front end expects.

    Luraph v14.7 / v14.8 / v14.9  ->  cli.py --engine 14.7|14.8|14.9
    Luraph v14.0 ... v14.6        ->  "auto"   (cli.py's own v14 auto-detect)
    Luraph v14.*  (no minor)      ->  "auto"
    Luraph v15 / v15.x / v15.1+   ->  deob.py --obfuscator luraph_v15
    anything else                 ->  None     (unknown, will try --detect)
    """
    v = version.strip().lstrip("vV")

    # exact v14.x that cli.py has a dedicated engine for
    if v in ("14.7", "14.8", "14.9"):
        return v

    # split into major / minor
    parts = v.split(".")
    major = parts[0]

    if major == "14":
        # 14.0 .. 14.6, or bare "14": let cli.py try its own detection
        return "auto"

    if major == "15":
        # any 15.x, including 15, 15.0, 15.1, 15.99
        return "luraph_v15"

    return None


def scan(path: Path) -> dict:
    """
    Look at a file's header and return:

        {
          "found":   bool,
          "version": "14.7" | "15" | "15.1" | None,
          "major":   "14" | "15" | None,
          "minor":   7 | 0 | None,
          "engine":  "14.7" | "luraph_v15" | "auto" | None,
          "banner":  "-- This file was protected using Luraph Obfuscator v14.7 [...]",
          "url":     "https://lura.ph/" | None,
        }
    """
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
