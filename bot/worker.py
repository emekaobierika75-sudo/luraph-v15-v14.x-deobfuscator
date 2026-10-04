"""
Worker: consumes job JSON files from /jobs/in, runs the deobfuscator
inside this (network-less, read-only) container, writes result JSON to
/jobs/out.

Job JSON:
    {
      "id": "abc123",
      "input": "/jobs/in/abc123.luau",
      "engine": "14.7" | "luraph_v15" | null,
      "mode": "full" | "trace" | "detect",
      "original_name": "sample.luau"
    }

Result JSON:
    {"output": "/jobs/out/abc123.luau", "elapsed": 12.3, "scan": {...}}
    {"detected": "Luraph v14.7", "engine": "14.7", "banner": "...", "scan": {...}}
    {"error": "..."}
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
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


def _log(msg: str) -> None:
    print(f"[worker] {msg}", flush=True)


def _read_stderr_tail(p: subprocess.CompletedProcess) -> str:
    err = p.stderr.decode("utf-8", "replace") if p.stderr else ""
    out = p.stdout.decode("utf-8", "replace") if p.stdout else ""
    text = err.strip() or out.strip() or f"exit code {p.returncode}"
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


def _run_full(inp: Path, job: dict) -> dict:
    job_id = job["id"]
    mode = job.get("mode", "full")

    work = WORK / job_id
    work.mkdir(parents=True, exist_ok=True)
    out_file = work / "out.luau"

    front, extra, scan_info = plan(inp, job.get("engine"), mode)

    cmd = [
        sys.executable,
        str(front),
        str(inp),
        "-o", str(out_file),
        "--timeout", str(RUN_TIMEOUT),
        "--budget", str(RUN_BUDGET),
        *extra,
    ]

    _log(f"job {job_id}: {' '.join(cmd)}")
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
        _log(f"job {job_id}: killed after {HARD_TIMEOUT}s")
        shutil.rmtree(work, ignore_errors=True)
        return {"error": f"deobfuscator killed after {HARD_TIMEOUT}s", "scan": scan_info}

    elapsed = time.time() - t0

    if p.returncode != 0 or not out_file.exists():
        err = _read_stderr_tail(p)
        _log(f"job {job_id}: failed ({elapsed:.1f}s)")
        shutil.rmtree(work, ignore_errors=True)
        return {"error": err, "scan": scan_info}

    final = OUT / f"{job_id}.luau"
    shutil.copyfile(out_file, final)
    shutil.rmtree(work, ignore_errors=True)
    _log(f"job {job_id}: ok ({elapsed:.1f}s, {final.stat().st_size} bytes)")
    return {"output": str(final), "elapsed": elapsed, "scan": scan_info}


def run_job(job: dict) -> dict:
    inp = Path(job["input"])
    if not inp.exists():
        return {"error": f"input file vanished: {inp}"}

    mode = job.get("mode", "full")
    try:
        if mode == "detect":
            return _run_detect(inp)
        return _run_full(inp, job)
    except Exception as e:
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
