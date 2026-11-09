from __future__ import annotations

import asyncio
import importlib.util
import threading
import unittest
from functools import partial
from pathlib import Path
from tempfile import SpooledTemporaryFile, TemporaryDirectory
from unittest import mock

FASTAPI_DEPS_AVAILABLE = all(
    importlib.util.find_spec(name) is not None for name in ("fastapi", "httpx2", "jinja2", "multipart")
)

if FASTAPI_DEPS_AVAILABLE:
    from fastapi import UploadFile
    from httpx2 import ASGITransport, AsyncClient

    from apps.dashboard import main, routes, scenarios, uploads


_MINIMAL_PLAN = b'{"terraform_version":"1.9.0","planned_values":{"root_module":{"resources":[]}}}'


@unittest.skipUnless(FASTAPI_DEPS_AVAILABLE, "dashboard dependencies are not installed")
class DashboardExecutionTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.app = main.create_app()
        await self.enterAsyncContext(self.app.router.lifespan_context(self.app))
        self.client = await self.enterAsyncContext(
            AsyncClient(
                transport=ASGITransport(app=self.app, raise_app_exceptions=False),
                base_url="http://testserver",
            )
        )

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

    async def test_cancelled_upload_keeps_staged_file_until_worker_finishes(self) -> None:
        loop = asyncio.get_running_loop()
        started = asyncio.Event()
        release = threading.Event()
        observed_paths: list[Path] = []
        analyze = self.app.state.engine.analyze_plan

        def blocked(plan_path: Path, *, title: str):
            observed_paths.append(plan_path)
            loop.call_soon_threadsafe(started.set)
            if not release.wait(timeout=10):
                raise AssertionError("test did not release the worker")
            self.assertEqual(plan_path.read_bytes(), _MINIMAL_PLAN)
            return analyze(plan_path, title=title)

        with (
            TemporaryDirectory() as temp_root,
            SpooledTemporaryFile() as source,
            mock.patch.object(uploads, "TemporaryDirectory", partial(TemporaryDirectory, dir=temp_root)),
            mock.patch.object(self.app.state.engine, "analyze_plan", side_effect=blocked),
        ):
            source.write(_MINIMAL_PLAN)
            source.seek(0)
            request = asyncio.create_task(
                uploads.analyze_upload(
                    UploadFile(file=source, filename="plan.json"),
                    title="Cancelled upload",
                    engine=self.app.state.engine,
                    execution=self.app.state.execution,
                )
            )
            try:
                await asyncio.wait_for(started.wait(), timeout=5)
                for _ in range(2):
                    request.cancel()
                    await asyncio.sleep(0)  # Deliver cancellation; this is a scheduler checkpoint, not a timing gate.
                    self.assertFalse(request.done())
                    self.assertTrue(observed_paths[0].is_file())
            finally:
                release.set()
                with self.assertRaises(asyncio.CancelledError):
                    await asyncio.wait_for(request, timeout=10)

            self.assertTrue(source.closed)
            self.assertEqual(list(Path(temp_root).iterdir()), [])
