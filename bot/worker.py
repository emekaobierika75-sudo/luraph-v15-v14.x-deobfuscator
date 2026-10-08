"""
Worker: consumes job JSON files from /jobs/in, runs the deobfuscator
inside this (network-less, read-only) container, writes result JSON to
/jobs/out.

Job JSON:
    {
      "id": "abc123",
      "input": "/jobs/in/abc123.luau",
      "engine": "14.7" | "luraph_v15" | null,
      "mode": "smart" | "full" | "trace" | "strings" | "detect",
      "original_name": "sample.luau"
    }

Result JSON:
    {"output": "...", "elapsed": 12.3, "scan": {...}, "mode_used": "full",
     "attempts": ["full"]}
    {"error": "...", "attempts": ["full", "strings", "trace"], "scan": {...}}
    {"detected": "Luraph v14.7", ...}
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from dispatcher import plan  # noqa: E402
from scanner import scan     # noqa: E402

JOBS_DIR = Path(os.environ.get("JOBS_DIR", "/jobs"))
IN = JOBS_DIR / "in"
OUT = JOBS_DIR / "out"
WORK = Path(os.environ.get("TMPDIR", "/tmp")) / "deobf_work"

DEOB_DIR = Path(os.environ.get("DEOB_DIR", "/app/deobf"))

HARD_TIMEOUT = 200
RUN_TIMEOUT = 90
RUN_BUDGET = 25
POLL_SECONDS = 0.5
MAX_LOG_CHARS = 2000

SMART_ORDER = ("full", "strings", "trace")


def _log(msg: str) -> None:
    print(f"[worker] {msg}", flush=True)


def _clean_traceback(text: str) -> str:
    """
    If stderr contains a Python traceback, drop the traceback frames and
    keep only:
      - the engine's own lines that came before the traceback
      - the final exception line (the actual error message)
    """
    if "Traceback (most recent call last):" not in text:
        return text

    lines = text.split("\n")

    # find the first traceback header
    tb_start = None
    for i, l in enumerate(lines):
        if "Traceback (most recent call last):" in l:
            tb_start = i
            break

    # last non-empty line is the exception summary
    last = ""
    for l in reversed(lines):
        if l.strip():
            last = l.strip()
            break

    if tb_start is None:
        return text
    head = "\n".join(lines[:tb_start]).rstrip()
    if head:
        return head + "\n\n" + last
    return last


def _read_stderr_tail(p: subprocess.CompletedProcess) -> str:
    err = p.stderr.decode("utf-8", "replace") if p.stderr else ""
    out = p.stdout.decode("utf-8", "replace") if p.stdout else ""
    text = err.strip() or out.strip() or f"exit code {p.returncode}"
    text = _clean_traceback(text)
    return text[-MAX_LOG_CHARS:]


def _run_detect(inp: Path) -> dict:
    info = scan(inp)
    if info["found"]:
        return {
            "detected": f"Luraph v{info['version']}",
            "engine": info["engine"],
            "banner": info["banner"],
            "scan": info,
        }
    return {"error": "no Luraph banner found in the first 8 KB"}


def _run_one(inp: Path, job: dict, mode: str, sub_id: str) -> dict:
    """Run a single mode. Always returns a dict; never raises."""
    work = WORK / sub_id
    work.mkdir(parents=True, exist_ok=True)
    out_file = work / "out.luau"

    try:
        front, extra, scan_info = plan(inp, job.get("engine"), mode)
    except Exception as e:
        shutil.rmtree(work, ignore_errors=True)
        return {
            "error": f"dispatch failed: {e!r}",
            "scan": {},
            "mode": mode,
        }

    cmd = [
        sys.executable,
        str(front),
        str(inp),
        "-o", str(out_file),
        "--timeout", str(RUN_TIMEOUT),
        "--budget", str(RUN_BUDGET),
        *extra,
    ]

    _log(f"job {sub_id}: mode={mode}: {' '.join(cmd)}")
    t0 = time.time()

    try:
        p = subprocess.run(
            cmd,
            cwd=str(DEOB_DIR),
            capture_output=True,
            timeout=HARD_TIMEOUT,
            env={
                "PATH": "/usr/bin:/bin",
                "PYTHONUNBUFFERED": "1",
                "HOME": "/tmp",
                "TMPDIR": str(WORK),
            },
        )
    except subprocess.TimeoutExpired:
        elapsed = time.time() - t0
        _log(f"job {sub_id}: mode={mode}: killed after {HARD_TIMEOUT}s")
        shutil.rmtree(work, ignore_errors=True)
        return {
            "error": f"deobfuscator killed after {HARD_TIMEOUT}s (mode={mode})",
            "scan": scan_info,
            "mode": mode,
            "elapsed": elapsed,
        }
    except Exception as e:
        elapsed = time.time() - t0
        _log(f"job {sub_id}: mode={mode}: subprocess exception {e!r}")
        shutil.rmtree(work, ignore_errors=True)
        return {
            "error": f"subprocess error: {e!r}",
            "scan": scan_info,
            "mode": mode,
            "elapsed": elapsed,
        }

    elapsed = time.time() - t0

    if p.returncode != 0 or not out_file.exists():
        err = _read_stderr_tail(p)
        _log(f"job {sub_id}: mode={mode}: failed ({elapsed:.1f}s)")
        shutil.rmtree(work, ignore_errors=True)
        return {
            "error": err,
            "scan": scan_info,
            "mode": mode,
            "elapsed": elapsed,
        }

    final = OUT / f"{sub_id}.luau"
    shutil.copyfile(out_file, final)
    shutil.rmtree(work, ignore_errors=True)
    _log(f"job {sub_id}: mode={mode}: ok ({elapsed:.1f}s, {final.stat().st_size} bytes)")
    return {
        "output": str(final),
        "elapsed": elapsed,
        "scan": scan_info,
        "mode": mode,
    }


def _run_smart(inp: Path, job: dict) -> dict:
    """
    Try each mode in SMART_ORDER. Return the first success; if all fail,
    return a merged error naming every mode that was attempted.
    """
    base_id = job["id"]
    attempts: list[str] = []
    last_err = ""
    last_scan: dict = {}
    total_start = time.time()
    per_mode_errors: list[tuple[str, str]] = []

    for i, mode in enumerate(SMART_ORDER):
        sub_id = f"{base_id}.{i}.{mode}"
        try:
            result = _run_one(inp, job, mode, sub_id)
        except Exception as e:  # noqa: BLE001
            _log(f"job {base_id}: mode={mode}: crashed in _run_one: {e!r}")
            traceback.print_exc()
            result = {"error": f"internal error in mode {mode}: {e!r}", "mode": mode}

        attempts.append(mode)
        last_scan = result.get("scan") or last_scan

        if "output" in result:
            result["mode_used"] = mode
            result["elapsed"] = time.time() - total_start
            result["attempts"] = attempts
            return result

        err = result.get("error", "")
        per_mode_errors.append((mode, err))
        last_err = err
        sub_out = OUT / f"{sub_id}.luau"
        sub_out.unlink(missing_ok=True)

    # all modes failed: build a compact report
    if per_mode_errors:
        parts = []
        for mode, err in per_mode_errors:
            first_line = (err.splitlines()[0] if err.splitlines() else "unknown error")
            parts.append(f"[{mode}] {first_line}")
        summary = "\n".join(parts)
    else:
        summary = last_err or "all modes failed"

    return {
        "error": summary,
        "attempts": attempts,
        "scan": last_scan,
    }


def run_job(job: dict) -> dict:
    inp = Path(job["input"])
    if not inp.exists():
        return {"error": f"input file vanished: {inp}"}

    mode = job.get("mode", "smart")
    try:
        if mode == "detect":
            return _run_detect(inp)
        if mode == "smart":
            return _run_smart(inp, job)
        return _run_one(inp, job, mode, job["id"])
    except Exception as e:  # noqa: BLE001
        traceback.print_exc()
        return {"error": f"worker exception: {e!r}"}


def _write_result(job_id: str, result: dict) -> None:
    tmp = OUT / f".{job_id}.json.tmp"
    tmp.write_text(json.dumps(result))
    tmp.replace(OUT / f"{job_id}.json")


def _sweep(jobfile: Path) -> None:
    try:
        job = json.loads(jobfile.read_text())
    except Exception as e:
        _log(f"bad job file {jobfile.name}: {e!r}")
        jobfile.unlink(missing_ok=True)
        return

    result = run_job(job)
    _write_result(job["id"], result)
    jobfile.unlink(missing_ok=True)
    Path(job["input"]).unlink(missing_ok=True)


def main() -> None:
    IN.mkdir(parents=True, exist_ok=True)
    OUT.mkdir(parents=True, exist_ok=True)
    WORK.mkdir(parents=True, exist_ok=True)

    _log(f"watching {IN} (jobs out -> {OUT})")
    _log(f"smart mode order: {' -> '.join(SMART_ORDER)}")

    while True:
        found = False
        for jobfile in sorted(IN.glob("*.json")):
            found = True
            _sweep(jobfile)
        if not found:
            time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
