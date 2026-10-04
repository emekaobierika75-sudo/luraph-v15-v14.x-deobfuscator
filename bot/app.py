"""
Single-container entrypoint for Render / Railway / Fly / any host that
runs one container per service and can't share a /jobs volume between
two services.

Runs the worker's job loop in a background thread and the Discord bot in
the main thread. If either dies, the container exits and the platform
restarts it.
"""

from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

JOBS_DIR = Path(os.environ.get("JOBS_DIR", "/jobs"))
(JOBS_DIR / "in").mkdir(parents=True, exist_ok=True)
(JOBS_DIR / "out").mkdir(parents=True, exist_ok=True)

import worker  # noqa: E402
import bot     # noqa: E402


def _worker_thread() -> None:
    try:
        worker.main()
    except Exception as e:  # noqa: BLE001
        print(f"[app] worker thread died: {e!r}", flush=True)


def main() -> None:
    t = threading.Thread(target=_worker_thread, name="worker", daemon=True)
    t.start()
    time.sleep(0.5)
    bot.main()


if __name__ == "__main__":
    main()
