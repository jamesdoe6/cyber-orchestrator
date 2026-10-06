"""Bounded background executor for scan runs (recreated on demand after shutdown)."""
from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

from .config import settings

_executor: ThreadPoolExecutor | None = None
_lock = threading.Lock()


def _ensure() -> ThreadPoolExecutor:
    global _executor
    with _lock:
        if _executor is None:
            _executor = ThreadPoolExecutor(
                max_workers=max(1, settings.max_concurrent_runs), thread_name_prefix="scan"
            )
        return _executor


def submit(fn, *args, **kwargs):
    try:
        return _ensure().submit(fn, *args, **kwargs)
    except RuntimeError:
        # Executor was shut down (e.g. after a lifespan restart) — recreate it.
        global _executor
        with _lock:
            _executor = None
        return _ensure().submit(fn, *args, **kwargs)


def shutdown() -> None:
    global _executor
    with _lock:
        ex, _executor = _executor, None
    if ex is not None:
        ex.shutdown(wait=False, cancel_futures=True)
