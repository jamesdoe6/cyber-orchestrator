"""Cancellation registry for in-flight runs.

Each executing run gets a :class:`RunControl` holding a cancel Event and a
reference to its live subprocess (when any). Cancelling sets the event and kills
the process; the worker observes the event and finalizes the run as cancelled.
Thread-safe: the cancel endpoint and the worker thread touch it concurrently.
"""
from __future__ import annotations

import threading


class RunControl:
    def __init__(self) -> None:
        self.event = threading.Event()
        self._proc = None
        self._lock = threading.Lock()

    @property
    def cancelled(self) -> bool:
        return self.event.is_set()

    def set_proc(self, proc) -> None:
        with self._lock:
            self._proc = proc
            already = self.event.is_set()
        if already and proc is not None and proc.poll() is None:
            self._kill(proc)

    def cancel(self) -> None:
        self.event.set()
        with self._lock:
            proc = self._proc
        if proc is not None and proc.poll() is None:
            self._kill(proc)

    @staticmethod
    def _kill(proc) -> None:
        try:
            proc.kill()
        except Exception:  # noqa: BLE001 - process may have just exited
            pass


_registry: dict[int, RunControl] = {}
_lock = threading.Lock()


def get_or_create(run_id: int) -> RunControl:
    with _lock:
        rc = _registry.get(run_id)
        if rc is None:
            rc = RunControl()
            _registry[run_id] = rc
        return rc


def get(run_id: int) -> RunControl | None:
    with _lock:
        return _registry.get(run_id)


def remove(run_id: int) -> None:
    with _lock:
        _registry.pop(run_id, None)


def cancel(run_id: int) -> bool:
    rc = get_or_create(run_id)  # pre-register so a not-yet-started run is cancelled too
    rc.cancel()
    return True
