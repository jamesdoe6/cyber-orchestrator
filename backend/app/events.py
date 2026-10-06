"""In-process event bus bridging background worker threads to async WebSockets.

Scans run in a thread pool (blocking subprocess). WebSocket handlers run on the
asyncio event loop. Workers publish events with :meth:`EventBus.publish`, which
hands each subscriber's asyncio.Queue a thread-safe ``put`` via the captured
event loop. WebSocket handlers drain their queue and forward to the client.
"""
from __future__ import annotations

import asyncio
from collections import defaultdict


class EventBus:
    def __init__(self) -> None:
        self._subs: dict[int, set[asyncio.Queue]] = defaultdict(set)
        self._loop: asyncio.AbstractEventLoop | None = None

    def set_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    def subscribe(self, engagement_id: int) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=2000)
        self._subs[engagement_id].add(q)
        return q

    def unsubscribe(self, engagement_id: int, q: asyncio.Queue) -> None:
        self._subs.get(engagement_id, set()).discard(q)

    def publish(self, engagement_id: int, event: dict) -> None:
        """Thread-safe: callable from a worker thread or the event loop."""
        loop = self._loop
        if loop is None:
            return
        for q in list(self._subs.get(engagement_id, ())):
            loop.call_soon_threadsafe(self._safe_put, q, event)

    @staticmethod
    def _safe_put(q: asyncio.Queue, event: dict) -> None:
        try:
            q.put_nowait(event)
        except asyncio.QueueFull:
            pass  # a slow client must never block the scan


bus = EventBus()
