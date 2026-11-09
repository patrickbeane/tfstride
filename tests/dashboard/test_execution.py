from __future__ import annotations

import asyncio
import gc
import importlib.util
import threading
import unittest
from collections.abc import Callable
from functools import partial
from pathlib import Path
from tempfile import SpooledTemporaryFile, TemporaryDirectory
from types import SimpleNamespace
from unittest import mock

FASTAPI_DEPS_AVAILABLE = all(
    importlib.util.find_spec(name) is not None for name in ("fastapi", "httpx2", "jinja2", "multipart")
)

if FASTAPI_DEPS_AVAILABLE:
    from anyio import CancelScope, fail_after, to_thread, wait_all_tasks_blocked
    from fastapi import UploadFile
    from httpx2 import ASGITransport, AsyncClient

    from apps.dashboard import execution, main, routes, scenarios, uploads


_MINIMAL_PLAN = b'{"terraform_version":"1.9.0","planned_values":{"root_module":{"resources":[]}}}'


class _WorkerProbe:
    """Hold submitted work and count dispatches without replacing the real worker pool."""

    def __init__(self) -> None:
        self.started = asyncio.Event()
        self.release = threading.Event()
        self.submitted = 0
        self.in_flight = 0
        self.peak_in_flight = 0
        self.admission_attempts = 0
        self.admission_changed = asyncio.Event()

    async def wait_for_attempts(self, count: int) -> None:
        # Staging/closing also awaits work. Observe the execution boundary so a
        # blocked upload cannot be mistaken for a request queued for analysis.
        with fail_after(5):
            while self.admission_attempts < count:
                self.admission_changed.clear()
                await self.admission_changed.wait()
        await _wait_for_blocked_tasks()

    async def run_sync(self, operation: Callable[[], object], **kwargs):
        loop = asyncio.get_running_loop()
        loop_thread = threading.get_ident()
        # Count before dispatch, so the assertion includes work queued inside a
        # thread pool whose threads may not have started yet.
        self.submitted += 1
        self.in_flight += 1
        self.peak_in_flight = max(self.peak_in_flight, self.in_flight)

        def blocked():
            if threading.get_ident() == loop_thread:
                raise AssertionError("synchronous work ran on the event loop")
            loop.call_soon_threadsafe(self.started.set)
            if not self.release.wait(timeout=10):
                raise AssertionError("test did not release the worker")
            return operation()

        try:
            return await to_thread.run_sync(blocked, **kwargs)
        finally:
            self.in_flight -= 1


async def _wait_for_blocked_tasks() -> None:
    # This observes task state, rather than assuming other requests have queued
    # after an arbitrary sleep. The timeout only protects against a hung test.
    with fail_after(5):
        await wait_all_tasks_blocked()


@unittest.skipUnless(FASTAPI_DEPS_AVAILABLE, "dashboard dependencies are not installed")
class DashboardExecutionTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.temp_root = Path(self.enterContext(TemporaryDirectory()))
        self.enterContext(
            mock.patch.object(uploads, "TemporaryDirectory", partial(TemporaryDirectory, dir=self.temp_root))
        )
        self.app = main.create_app()
        await self.enterAsyncContext(self.app.router.lifespan_context(self.app))
        self.client = await self.enterAsyncContext(
            AsyncClient(
                transport=ASGITransport(app=self.app, raise_app_exceptions=False),
                base_url="http://testserver",
            )
        )

    def tearDown(self) -> None:
        self.assertEqual(list(self.temp_root.iterdir()), [], "staged upload files must be cleaned up")

    def _probe(self) -> _WorkerProbe:
        probe = _WorkerProbe()
        run = execution.DashboardExecution.run

        async def observe_admission(executor, operation):
            probe.admission_attempts += 1
            probe.admission_changed.set()
            return await run(executor, operation)

        self.enterContext(mock.patch.object(execution.DashboardExecution, "run", observe_admission))
        # Patch only the dashboard's reference, leaving Starlette/AnyIO I/O real.
        self.enterContext(mock.patch.object(execution, "to_thread", SimpleNamespace(run_sync=probe.run_sync)))
        self.addCleanup(probe.release.set)
        return probe

    def _upload(self, filename: str = "plan.json") -> UploadFile:
        source = self.enterContext(SpooledTemporaryFile())
        source.write(_MINIMAL_PLAN)
        source.seek(0)
        return UploadFile(file=source, filename=filename)

    async def _post_plan(self, filename: str, *, endpoint: str = "/api/analyze", data: bytes = _MINIMAL_PLAN):
        return await self.client.post(
            endpoint,
            data={"title": filename},
            files={"plan": (filename, data, "application/json")},
        )

    async def _start_cancellable_upload(self, upload: UploadFile, cancellation: str):
        scope_ready = asyncio.get_running_loop().create_future()

        async def analyze() -> None:
            with CancelScope() as scope:
                scope_ready.set_result(scope)
                await uploads.analyze_upload(
                    upload,
                    title="Cancelled upload",
                    engine=self.app.state.engine,
                    execution=self.app.state.execution,
                )

        request = asyncio.create_task(analyze())
        scope = await scope_ready
        cancel = request.cancel if cancellation == "asyncio" else scope.cancel
        return request, cancel

    def _assert_cancellation_result(self, result: object, cancellation: str) -> None:
        if cancellation == "asyncio":
            self.assertIsInstance(result, asyncio.CancelledError)
        else:
            # An AnyIO scope suppresses its own cancellation after cleanup.
            self.assertIsNone(result)

    async def _assert_health_during_request(
        self,
        target: object,
        attribute: str,
        endpoint: str,
        *,
        data: bytes = _MINIMAL_PLAN,
        expected_status: int = 200,
    ) -> None:
        loop = asyncio.get_running_loop()
        loop_thread = threading.get_ident()
        started = asyncio.Event()
        release = threading.Event()
        original = getattr(target, attribute)

        def blocked(*args, **kwargs):
            # Fail immediately if the pipeline regresses onto the event loop,
            # instead of deadlocking that loop waiting for the test to release it.
            self.assertNotEqual(threading.get_ident(), loop_thread)
            loop.call_soon_threadsafe(started.set)
            if not release.wait(timeout=10):
                raise AssertionError("test did not release the worker")
            return original(*args, **kwargs)

        with mock.patch.object(target, attribute, side_effect=blocked) as work:
            if endpoint in {"/analyze", "/api/analyze"}:
                request = asyncio.create_task(
                    self.client.post(endpoint, files={"plan": ("plan.json", data, "application/json")})
                )
            else:
                request = asyncio.create_task(self.client.get(endpoint))
            try:
                await asyncio.wait_for(started.wait(), timeout=5)
                health = await asyncio.wait_for(self.client.get("/healthz"), timeout=5)
                self.assertEqual(health.status_code, 200)
                self.assertEqual(health.json(), {"status": "ok"})
                self.assertFalse(request.done(), "health must respond while synchronous work is still blocked")
            finally:
                release.set()
                response = await asyncio.wait_for(request, timeout=10)

        self.assertGreater(work.call_count, 0)
        self.assertEqual(response.status_code, expected_status)

    async def test_health_responds_during_upload_analysis_and_report_generation(self) -> None:
        for endpoint in ("/api/analyze", "/analyze"):
            for target, attribute in (
                (self.app.state.engine, "analyze_plan"),
                (uploads, "build_json_report_payload"),
                (uploads, "render_markdown"),
            ):
                with self.subTest(endpoint=endpoint, stage=attribute):
                    await self._assert_health_during_request(target, attribute, endpoint)

    async def test_health_responds_during_warm_demo_analysis(self) -> None:
        await self.app.state.execution.run(partial(scenarios.get_demo_scenarios, self.app, self.app.state.engine))

        await self._assert_health_during_request(self.app.state.engine, "analyze_plan", "/demo/safe")

    async def test_health_responds_during_html_context_and_template_rendering(self) -> None:
        await self.app.state.execution.run(partial(scenarios.get_demo_scenarios, self.app, self.app.state.engine))
        for endpoint in ("/analyze", "/demo/safe"):
            for target, attribute in (
                (routes, "_report_context"),
                (main.TEMPLATES, "TemplateResponse"),
            ):
                with self.subTest(endpoint=endpoint, stage=attribute):
                    await self._assert_health_during_request(target, attribute, endpoint)

    async def test_health_responds_during_cold_catalog_analysis_from_all_callers(self) -> None:
        for endpoint, data, expected_status in (
            ("/scenarios", _MINIMAL_PLAN, 200),
            ("/demo/safe", _MINIMAL_PLAN, 200),
            ("/analyze", b"", 400),
        ):
            with self.subTest(endpoint=endpoint):
                self.app.state.demo_scenarios = None
                self.app.state.demo_scenarios_by_id = None
                await self._assert_health_during_request(
                    self.app.state.engine,
                    "analyze_plan",
                    endpoint,
                    data=data,
                    expected_status=expected_status,
                )

    async def test_mixed_requests_share_one_worker_and_build_the_cold_catalog_once(self) -> None:
        probe = self._probe()
        engine = self.app.state.engine
        with (
            mock.patch.object(engine, "analyze_plan", wraps=engine.analyze_plan) as analyze,
            mock.patch.object(scenarios, "build_demo_scenarios", wraps=scenarios.build_demo_scenarios) as build_catalog,
        ):
            requests = [asyncio.create_task(self._post_plan("first.json"))]
            try:
                await asyncio.wait_for(probe.started.wait(), timeout=5)
                requests.extend(asyncio.create_task(self._post_plan(f"queued-{index}.json")) for index in range(4))
                requests.extend(
                    (
                        asyncio.create_task(self._post_plan("html.json", endpoint="/analyze")),
                        asyncio.create_task(self.client.get("/demo/safe")),
                        asyncio.create_task(self.client.get("/demo/safe")),
                        asyncio.create_task(self.client.get("/scenarios")),
                        asyncio.create_task(self.client.get("/scenarios")),
                        asyncio.create_task(self._post_plan("empty.json", endpoint="/analyze", data=b"")),
                    )
                )
                await probe.wait_for_attempts(len(requests))

                self.assertTrue(all(not request.done() for request in requests))
                self.assertEqual(probe.submitted, 1, "queued requests must not submit more worker jobs")
                build_catalog.assert_not_called()
                health = await asyncio.wait_for(self.client.get("/healthz"), timeout=5)
                self.assertEqual(health.json(), {"status": "ok"})
            finally:
                probe.release.set()
                responses = await asyncio.wait_for(asyncio.gather(*requests), timeout=10)

            self.assertEqual([response.status_code for response in responses], [200] * 10 + [400])
            for index, filename in enumerate(["first.json", *(f"queued-{index}.json" for index in range(4))]):
                self.assertEqual(responses[index].json()["title"], filename)
                self.assertEqual(responses[index].json()["analyzed_file"], filename)
            self.assertEqual(responses[6].text, responses[7].text)
            self.assertEqual(responses[8].text, responses[9].text)
            build_catalog.assert_called_once_with(engine)
            catalog = self.app.state.demo_scenarios
            self.assertEqual(len(catalog), len(scenarios.DEMO_SCENARIO_DEFINITIONS))
            self.assertEqual(analyze.call_count, len(catalog) + 6 + 2)  # Catalog, uploads, and demo reports.
            self.assertEqual(list(self.app.state.demo_scenarios_by_id), [item.scenario_id for item in catalog])
            for item in catalog:
                self.assertIs(self.app.state.demo_scenarios_by_id[item.scenario_id], item)

            # Warm gallery requests reuse the fully populated cache.
            self.assertEqual((await self.client.get("/scenarios")).text, responses[8].text)
            build_catalog.assert_called_once()
            self.assertEqual(analyze.call_count, len(catalog) + 6 + 2)

        self.assertEqual(probe.peak_in_flight, 1)
        self.assertEqual(probe.in_flight, 0)

    async def test_analysis_capacity_is_independent_of_starlette_io_capacity(self) -> None:
        probe = self._probe()
        io_limiter = to_thread.current_default_thread_limiter()
        original_tokens = io_limiter.total_tokens
        io_limiter.total_tokens = 1
        request = None
        try:
            async with io_limiter:
                request = asyncio.create_task(self._post_plan("independent.json"))
                await asyncio.wait_for(probe.started.wait(), timeout=5)
                self.assertFalse(request.done(), "analysis must start even when default I/O capacity is occupied")

            self.assertEqual(
                await asyncio.wait_for(to_thread.run_sync(lambda: "I/O completed"), timeout=5),
                "I/O completed",
            )
            self.assertFalse(request.done(), "I/O must complete while the analysis worker remains occupied")
        finally:
            probe.release.set()
            io_limiter.total_tokens = original_tokens
            if request is not None:
                response = await asyncio.wait_for(request, timeout=10)

        self.assertEqual(response.status_code, 200)

    async def test_application_instances_have_independent_worker_capacity(self) -> None:
        probe = self._probe()
        other_app = main.create_app()
        async with (
            other_app.router.lifespan_context(other_app),
            AsyncClient(transport=ASGITransport(app=other_app), base_url="http://testserver") as other_client,
        ):
            requests = [asyncio.create_task(self._post_plan("first-app.json"))]
            try:
                await asyncio.wait_for(probe.started.wait(), timeout=5)
                requests.append(
                    asyncio.create_task(
                        other_client.post(
                            "/api/analyze", files={"plan": ("second-app.json", _MINIMAL_PLAN, "application/json")}
                        )
                    )
                )
                await probe.wait_for_attempts(2)
                self.assertTrue(all(not request.done() for request in requests))
                self.assertEqual(probe.submitted, 2, "each application must be able to admit its own worker")
            finally:
                probe.release.set()
                responses = await asyncio.wait_for(asyncio.gather(*requests), timeout=10)

        self.assertEqual([response.status_code for response in responses], [200, 200])
        self.assertEqual(probe.peak_in_flight, 2)
        self.assertEqual(probe.in_flight, 0)

    async def test_cancellation_during_staging_closes_disk_upload_and_removes_partial_file(self) -> None:
        for cancellation in ("asyncio", "anyio"):
            with self.subTest(cancellation=cancellation):
                probe = self._probe()
                source = self._upload("cancelled.json")
                source.file.rollover()
                reading = asyncio.Event()
                never = asyncio.Event()
                read = source.read
                reads = 0

                async def read_until_cancelled(size: int, read_source=read, read_started=reading, release_read=never):
                    nonlocal reads
                    reads += 1
                    if reads == 2:
                        read_started.set()
                        await release_read.wait()
                    return await read_source(size)

                with (
                    mock.patch.object(source, "read", side_effect=read_until_cancelled),
                    mock.patch.object(uploads, "UPLOAD_READ_CHUNK_BYTES", 13),
                ):
                    request, cancel = await self._start_cancellable_upload(source, cancellation)
                    try:
                        await asyncio.wait_for(reading.wait(), timeout=5)
                        self.assertEqual(len(list(self.temp_root.glob("*/cancelled.json"))), 1)
                    finally:
                        cancel()
                        results = await asyncio.wait_for(asyncio.gather(request, return_exceptions=True), timeout=5)

                self._assert_cancellation_result(results[0], cancellation)
                self.assertTrue(source.file.closed)
                self.assertEqual(probe.submitted, 0)
                self.assertEqual(list(self.temp_root.iterdir()), [])

    async def test_queued_cancellation_removes_upload_without_submitting_work(self) -> None:
        for cancellation in ("asyncio", "anyio"):
            with self.subTest(cancellation=cancellation):
                probe = self._probe()
                source = self._upload("cancelled.json")
                # Exercise real asynchronous close for uploads spooled to disk.
                source.file.rollover()
                engine = self.app.state.engine
                with mock.patch.object(engine, "analyze_plan", wraps=engine.analyze_plan) as analyze:
                    requests = [asyncio.create_task(self._post_plan("occupant.json"))]
                    try:
                        await asyncio.wait_for(probe.started.wait(), timeout=5)
                        cancelled, cancel = await self._start_cancellable_upload(source, cancellation)
                        requests.append(cancelled)
                        await probe.wait_for_attempts(2)
                        staged = list(self.temp_root.glob("*/cancelled.json"))
                        self.assertEqual(len(staged), 1)
                        self.assertTrue(source.file.closed)
                        self.assertFalse(cancelled.done())

                        cancel()
                        result = (await asyncio.wait_for(asyncio.gather(cancelled, return_exceptions=True), timeout=5))[
                            0
                        ]
                        self._assert_cancellation_result(result, cancellation)
                        self.assertFalse(staged[0].parent.exists())
                        self.assertFalse(requests[0].done())
                        self.assertEqual(probe.submitted, 1)

                        requests.append(asyncio.create_task(self._post_plan("survivor.json")))
                        await probe.wait_for_attempts(3)
                        self.assertFalse(requests[-1].done())
                    finally:
                        probe.release.set()
                        results = await asyncio.wait_for(asyncio.gather(*requests, return_exceptions=True), timeout=10)

                self.assertEqual(results[0].status_code, 200)
                self.assertEqual(results[-1].status_code, 200)
                self.assertEqual(
                    [call.args[0].name for call in analyze.call_args_list], ["occupant.json", "survivor.json"]
                )
                self.assertEqual(probe.submitted, 2)
                self.assertEqual(probe.peak_in_flight, 1)
                self.assertEqual(list(self.temp_root.iterdir()), [])

    async def test_running_cancellation_joins_success_or_failure_before_releasing_files_and_capacity(self) -> None:
        loop = asyncio.get_running_loop()
        unhandled: list[dict[str, object]] = []
        original_handler = loop.get_exception_handler()
        loop.set_exception_handler(lambda _loop, context: unhandled.append(context))
        self.addCleanup(loop.set_exception_handler, original_handler)

        for cancellation in ("asyncio", "anyio"):
            for worker_fails in (False, True):
                with self.subTest(cancellation=cancellation, worker_fails=worker_fails):
                    unhandled.clear()
                    probe = self._probe()
                    source = self._upload("cancelled.json")
                    source.file.rollover()
                    analyze = self.app.state.engine.analyze_plan
                    finished: list[Path] = []

                    def analyze_after_cancellation(
                        plan_path: Path,
                        *,
                        title: str,
                        completed_paths=finished,
                        fail=worker_fails,
                        run_analysis=analyze,
                    ):
                        if plan_path.name == "cancelled.json":
                            self.assertEqual(plan_path.read_bytes(), _MINIMAL_PLAN)
                            completed_paths.append(plan_path)
                            if fail:
                                raise RuntimeError("private worker failure after cancellation")
                        return run_analysis(plan_path, title=title)

                    with mock.patch.object(
                        self.app.state.engine, "analyze_plan", side_effect=analyze_after_cancellation
                    ):
                        cancelled, cancel = await self._start_cancellable_upload(source, cancellation)
                        requests = [cancelled]
                        try:
                            await asyncio.wait_for(probe.started.wait(), timeout=5)
                            staged = list(self.temp_root.glob("*/cancelled.json"))
                            self.assertEqual(len(staged), 1)
                            self.assertTrue(source.file.closed)
                            requests.append(asyncio.create_task(self._post_plan("survivor.json")))
                            await probe.wait_for_attempts(2)

                            for _ in range(2):
                                cancel()
                                await _wait_for_blocked_tasks()
                                self.assertFalse(cancelled.done())
                                self.assertTrue(staged[0].is_file())
                                self.assertFalse(requests[-1].done())
                                self.assertEqual(probe.submitted, 1, "cancellation must retain worker admission")
                        finally:
                            probe.release.set()
                            results = await asyncio.wait_for(
                                asyncio.gather(*requests, return_exceptions=True), timeout=10
                            )

                    self._assert_cancellation_result(results[0], cancellation)
                    self.assertEqual(results[-1].status_code, 200)
                    self.assertEqual(results[-1].json()["title"], "survivor.json")
                    self.assertEqual(finished, staged, "the cancelled request must join its worker")
                    self.assertEqual(probe.submitted, 2)
                    self.assertEqual(probe.peak_in_flight, 1)
                    self.assertFalse(staged[0].parent.exists())
                    self.assertEqual(list(self.temp_root.iterdir()), [])
                    gc.collect()
                    await _wait_for_blocked_tasks()
                    self.assertEqual(unhandled, [], "cancelled requests must retrieve worker failures")

    async def test_analysis_and_rendering_failures_release_capacity_for_queued_requests(self) -> None:
        for target, attribute in ((self.app.state.engine, "analyze_plan"), (uploads, "render_markdown")):
            with self.subTest(stage=attribute):
                probe = self._probe()
                original = getattr(target, attribute)
                calls = 0

                def fail_once(*args, run_original=original, **kwargs):
                    nonlocal calls
                    calls += 1
                    if calls == 1:
                        raise RuntimeError("private worker failure")
                    return run_original(*args, **kwargs)

                with mock.patch.object(target, attribute, side_effect=fail_once):
                    requests = [asyncio.create_task(self._post_plan("failure.json"))]
                    try:
                        await asyncio.wait_for(probe.started.wait(), timeout=5)
                        requests.append(asyncio.create_task(self._post_plan("recovery.json")))
                        await probe.wait_for_attempts(2)
                        self.assertEqual(probe.submitted, 1)
                    finally:
                        probe.release.set()
                        responses = await asyncio.wait_for(asyncio.gather(*requests), timeout=10)

                self.assertEqual(responses[0].status_code, 500)
                self.assertNotIn("private worker failure", responses[0].text)
                self.assertEqual(responses[1].status_code, 200)
                self.assertEqual(responses[1].json()["title"], "recovery.json")
                self.assertEqual(probe.submitted, 2)
                self.assertEqual(probe.peak_in_flight, 1)
                self.assertEqual(probe.in_flight, 0)
                self.assertEqual(list(self.temp_root.iterdir()), [])
