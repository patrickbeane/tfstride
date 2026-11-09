from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
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
            return await await_completion(to_thread.run_sync(operation, limiter=self._thread_limiter))


async def await_completion(operation: Awaitable[_Result]) -> _Result:
    """Defer request cancellation until owned work or resource cleanup finishes."""
    task = asyncio.ensure_future(operation)
    try:
        # wait() leaves the task untouched by request cancellation. Keep ownership
        # of its result, including failures after cancellation.
        await asyncio.wait({task})
        return task.result()
    except asyncio.CancelledError:
        # Keep the caller's resources until completion, even if cancellation is
        # requested again. Shielding also defers AnyIO scope cancellation.
        with CancelScope(shield=True):
            while not task.done():
                try:
                    await asyncio.wait({task})
                except asyncio.CancelledError:
                    continue
        if not task.cancelled():
            task.exception()  # Retrieve a failure before propagating cancellation.
        raise
