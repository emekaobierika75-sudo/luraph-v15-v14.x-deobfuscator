"""
Pick the right deobfuscator front end for a job.

Order of preference:
    1. the caller's explicit `engine` argument
    2. the Luraph banner found in the file header (scanner.py)
    3. deob.py --detect (plugin-based detectors)
    4. cli.py --engine auto  (v14.x shape-based detection)
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

from scanner import scan

DEOB_DIR = Path("/app/deobf")
CLI_PY = DEOB_DIR / "cli.py"
DEOB_PY = DEOB_DIR / "deob.py"

V14_EXACT_RE = re.compile(r"^v?14\.(7|8|9)$")
V14_ANY_RE = re.compile(r"^v?14(?:\.\d+)?$")
V15_ANY_RE = re.compile(r"^v?15(?:\.\d+)?$")


def _run(cmd: list[str], timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        cwd=str(DEOB_DIR),
        capture_output=True,
        timeout=timeout,
        env={"PATH": "/usr/bin:/bin", "PYTHONUNBUFFERED": "1", "HOME": "/tmp"},
    )


def detect_obfuscator(input_path: Path) -> str | None:
    try:
        p = _run([sys.executable, str(DEOB_PY), str(input_path), "--detect"], timeout=30)
    except subprocess.TimeoutExpired:
        return None
    if p.returncode != 0:
        return None
    lines = p.stdout.decode("utf-8", "replace").strip().splitlines()
    if not lines:
        return None
    return lines[0].split("\t", 1)[0] or None


def _resolve_engine(input_path: Path, explicit: str | None) -> tuple[str | None, dict]:
    info = scan(input_path)
    if explicit:
        return explicit, info
    if info["found"] and info["engine"]:
        return info["engine"], info
    return None, info


def _frontend_for(engine: str, mode: str) -> tuple[Path, list[str]]:
    """
    mode: "full" | "trace" | "strings"

    full    -> dedicated engine, --trace-fallback on v14 (mapper often can't
               find closure makers on unusual layouts; --trace-fallback means
               we still get a behavior trace instead of a hard failure)
    trace   -> --no-devirt (skips the mapper entirely)
    strings -> --strings --trace-fallback (dump recovered strings; keep whatever
               trace exists even if devirt can't finish)
    """
    extra: list[str] = []

    if mode == "trace":
        extra.append("--no-devirt")
    elif mode == "strings":
        extra.append("--strings")
        extra.append("--trace-fallback")

    e = engine.strip().lower()

    # v14.7 / 14.8 / 14.9 -> dedicated engine
    if V14_EXACT_RE.match(e):
        args = ["--engine", e.lstrip("v"), *extra]
        if mode == "full":
            args.append("--trace-fallback")
        return CLI_PY, args

    # bare "14", "14.0".."14.6", or the scanner's "auto"
    if e == "auto" or V14_ANY_RE.match(e):
        args = ["--engine", "auto", *extra]
        if mode == "full":
            args.append("--trace-fallback")
        return CLI_PY, args

    # 15, 15.0, 15.1, ...
    if e in ("v15", "15", "luraph_v15", "luraphv15") or V15_ANY_RE.match(e):
        return DEOB_PY, ["--obfuscator", "luraph_v15", *extra]

    # any other plugin name -> deob.py
    return DEOB_PY, ["--obfuscator", engine, *extra]


def plan(input_path: Path, engine: str | None, mode: str) -> tuple[Path, list[str], dict]:
    """
    Public entrypoint used by the worker.

    Returns (frontend, extra_args, scan_info).
    """
    resolved, info = _resolve_engine(input_path, engine)

    if resolved is None:
        detected = detect_obfuscator(input_path)
        if detected in ("luraph_v15", "ironbrew1", "generic"):
            resolved = detected
        else:
            resolved = "auto"

    front, extra = _frontend_for(resolved, mode)
    return front, extra, info


def describe_dispatch(scan_info: dict, engine: str | None) -> str:
    if engine:
        return f"engine forced to `{engine}`"

    if not scan_info.get("found"):
        return "no header banner — letting the tool auto-detect"

    v = scan_info["version"]
    major = scan_info["major"]

    if major == "14":
        if v in ("14.7", "14.8", "14.9"):
            return f"engine auto: `{v}` (dedicated)"
        return f"detected v{v} — no dedicated engine, falling back to `14-auto`"

    if major == "15":
        return f"engine auto: `luraph_v15` (covers v{v})"

    return f"detected v{v} — unknown major, letting the tool auto-detect"
