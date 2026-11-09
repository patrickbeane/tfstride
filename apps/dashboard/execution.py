from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import TypeVar

from anyio import CancelScope, CapacityLimiter, Lock, to_thread

_Result = TypeVar("_Result")


class DashboardExecution:
    """Serialize synchronous dashboard work for one application asyncio loop.

    The admission lock lets queued requests cancel before submitting work. The
    dedicated thread limiter avoids consuming Starlette's shared I/O capacity.
    Started work is always joined before returning, so callers can safely own
    temporary files. This includes direct asyncio cancellation from the server,
    which AnyIO's worker cancellation shield alone does not defer.
    """

    def __init__(self) -> None:
        self._admission = Lock()
        self._thread_limiter = CapacityLimiter(1)

    async def run(self, operation: Callable[[], _Result]) -> _Result:
        async with self._admission:
            task = asyncio.create_task(to_thread.run_sync(operation, limiter=self._thread_limiter))
            try:
                return await asyncio.shield(task)
            except asyncio.CancelledError:
                # Keep both the admission slot and the caller's resources until
                # the worker finishes, even if cancellation is requested again.
                with CancelScope(shield=True):
                    while not task.done():
                        try:
                            await asyncio.shield(task)
                        except asyncio.CancelledError:
                            continue
                        except Exception:
                            break
                if not task.cancelled():
                    task.exception()  # Retrieve a worker failure before propagating cancellation.
                raise
