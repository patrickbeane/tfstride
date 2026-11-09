from __future__ import annotations

import importlib.util
import json
import re
import unittest
from collections.abc import AsyncIterator
from functools import partial
from html import unescape
from pathlib import Path
from tempfile import SpooledTemporaryFile, TemporaryDirectory
from unittest import mock

from tests.helpers.paths import FIXTURES_DIR
from tfstride.app import TfStride
from tfstride.input.terraform_plan import TerraformPlanLoadError
from tfstride.reporting.json_report import build_json_report_payload
from tfstride.reporting.markdown import render_markdown

FASTAPI_DEPS_AVAILABLE = all(
    importlib.util.find_spec(name) is not None for name in ("fastapi", "httpx2", "jinja2", "multipart")
)

if FASTAPI_DEPS_AVAILABLE:
    from fastapi import Request, UploadFile
    from fastapi.responses import HTMLResponse
    from httpx2 import ASGITransport, AsyncClient
    from starlette.types import Receive, Scope, Send

    from apps.dashboard import uploads
    from apps.dashboard.main import create_app


_MINIMAL_PLAN = b'{"terraform_version":"1.9.0","planned_values":{"root_module":{"resources":[]}}}'
_MULTIPART_BOUNDARY = "dashboard-upload-test"
_MULTIPART_PREFIX = (
    f"--{_MULTIPART_BOUNDARY}\r\n"
    'Content-Disposition: form-data; name="plan"; filename="plan.json"\r\n'
    "Content-Type: application/json\r\n\r\n"
).encode()
_MULTIPART_SUFFIX = f"\r\n--{_MULTIPART_BOUNDARY}--\r\n".encode()


@unittest.skipUnless(FASTAPI_DEPS_AVAILABLE, "dashboard dependencies are not installed")
class DashboardUploadTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.temp_root = Path(self.enterContext(TemporaryDirectory()))
        self.enterContext(
            mock.patch.object(uploads, "TemporaryDirectory", partial(TemporaryDirectory, dir=self.temp_root))
        )
        self.app = create_app()
        # Exercise upload responses independently of lazy demo catalog construction.
        self.app.state.demo_scenarios = ()
        self.engine = self.app.state.engine
        await self.enterAsyncContext(self.app.router.lifespan_context(self.app))
        self.client = await self.enterAsyncContext(
            AsyncClient(
                transport=ASGITransport(app=self.app, raise_app_exceptions=False),
                base_url="http://testserver",
            )
        )

    def tearDown(self) -> None:
        self.assertEqual(list(self.temp_root.iterdir()), [], "staged upload files must be cleaned up")

    def _upload(self, data: bytes, filename: str | None = "plan.json") -> UploadFile:
        source = SpooledTemporaryFile(max_size=uploads.UPLOAD_READ_CHUNK_BYTES)
        self.addCleanup(source.close)
        source.write(data)
        source.seek(0)
        return UploadFile(file=source, filename=filename)

    async def test_staged_file_lives_through_analysis_and_rendering_then_is_removed(self) -> None:
        source = self._upload(_MINIMAL_PLAN, "../../nested/plan.json")
        observed_paths: list[Path] = []
        stages: list[str] = []
        analyze = self.engine.analyze_plan

        def analyze_with_live_file(plan_path: Path, *, title: str):
            self.assertEqual(plan_path.read_bytes(), _MINIMAL_PLAN)
            self.assertEqual(plan_path.name, "plan.json")
            self.assertEqual(plan_path.parent.parent, self.temp_root)
            observed_paths.append(plan_path)
            stages.append("analysis")
            return analyze(plan_path, title=title)

        def build_payload_with_live_file(result):
            self.assertTrue(observed_paths[0].is_file())
            stages.append("payload")
            return build_json_report_payload(result)

        def render_with_live_file(result):
            self.assertTrue(observed_paths[0].is_file())
            stages.append("markdown")
            return render_markdown(result)

        with (
            mock.patch.object(self.engine, "analyze_plan", side_effect=analyze_with_live_file),
            mock.patch.object(uploads, "build_json_report_payload", side_effect=build_payload_with_live_file),
            mock.patch.object(uploads, "render_markdown", side_effect=render_with_live_file),
        ):
            analysis = await uploads.analyze_upload(source, title="Upload lifecycle", engine=self.engine)

        self.assertEqual(stages, ["analysis", "payload", "markdown"])
        self.assertTrue(source.file.closed)
        self.assertFalse(observed_paths[0].exists())
        self.assertFalse(observed_paths[0].parent.exists())
        self.assertEqual(analysis.payload["title"], "Upload lifecycle")
        self.assertEqual(analysis.payload["analyzed_file"], "plan.json")
        self.assertEqual(analysis.payload["analyzed_path"], "plan.json")
        self.assertNotIn(str(self.temp_root), analysis.markdown_report)

    async def test_missing_filename_and_empty_title_use_defaults(self) -> None:
        for filename in (None, "", "/"):
            with self.subTest(filename=filename):
                source = self._upload(_MINIMAL_PLAN, filename)

                analysis = await uploads.analyze_upload(source, title="", engine=self.engine)

                self.assertEqual(analysis.payload["analyzed_file"], "uploaded-plan.json")
                self.assertEqual(analysis.payload["analyzed_path"], "uploaded-plan.json")
                self.assertEqual(analysis.payload["title"], uploads.DEFAULT_REPORT_TITLE)
                self.assertTrue(source.file.closed)

    async def test_file_at_size_limit_is_accepted_using_bounded_reads(self) -> None:
        source = self._upload(_MINIMAL_PLAN)
        with (
            mock.patch.object(uploads, "MAX_UPLOAD_BYTES", len(_MINIMAL_PLAN)),
            mock.patch.object(uploads, "UPLOAD_READ_CHUNK_BYTES", 13),
            mock.patch.object(source, "read", wraps=source.read) as read,
        ):
            analysis = await uploads.analyze_upload(source, title="Exact limit", engine=self.engine)

        self.assertEqual(analysis.payload["title"], "Exact limit")
        self.assertGreater(read.call_count, 1)
        self.assertTrue(all(call == mock.call(13) for call in read.call_args_list))
        self.assertTrue(source.file.closed)

    async def test_oversized_file_stops_reading_and_skips_analysis(self) -> None:
        source = self._upload(_MINIMAL_PLAN + b" " * 1000)
        with (
            mock.patch.object(uploads, "MAX_UPLOAD_BYTES", len(_MINIMAL_PLAN)),
            mock.patch.object(uploads, "UPLOAD_READ_CHUNK_BYTES", 13),
            mock.patch.object(source, "read", wraps=source.read) as read,
            mock.patch.object(self.engine, "analyze_plan") as analyze,
            self.assertRaises(uploads.DashboardInputError) as raised,
        ):
            await uploads.analyze_upload(source, title="Too large", engine=self.engine)

        self.assertIn("exceeds", raised.exception.public_message)
        self.assertLessEqual(read.call_count, len(_MINIMAL_PLAN) // 13 + 1)
        analyze.assert_not_called()
        self.assertTrue(source.file.closed)

    async def test_empty_or_invalid_uploads_close_the_source_and_remove_staged_files(self) -> None:
        for data, error_type in (
            (b"", uploads.DashboardInputError),
            (b"{", TerraformPlanLoadError),
            (b"{}", TerraformPlanLoadError),
            (b"[]", TerraformPlanLoadError),
        ):
            with self.subTest(data=data):
                source = self._upload(data)
                with self.assertRaises(error_type):
                    await uploads.analyze_upload(source, title="Invalid", engine=self.engine)
                self.assertTrue(source.file.closed)
                self.assertEqual(list(self.temp_root.iterdir()), [])

    async def test_read_failure_closes_the_source_and_removes_partial_file(self) -> None:
        source = self._upload(_MINIMAL_PLAN)
        error = OSError("upload read failed")
        with (
            mock.patch.object(source, "read", side_effect=[b"{", error]),
            mock.patch.object(self.engine, "analyze_plan") as analyze,
            self.assertRaises(OSError) as raised,
        ):
            await uploads.analyze_upload(source, title="Read failure", engine=self.engine)

        self.assertIs(raised.exception, error)
        analyze.assert_not_called()
        self.assertTrue(source.file.closed)

    async def test_analysis_and_rendering_failures_propagate_after_cleanup(self) -> None:
        for target, name in (
            (self.engine, "analyze_plan"),
            (uploads, "build_json_report_payload"),
            (uploads, "render_markdown"),
        ):
            with self.subTest(stage=name):
                source = self._upload(_MINIMAL_PLAN)
                error = RuntimeError(f"{name} failed")
                with mock.patch.object(target, name, side_effect=error), self.assertRaises(RuntimeError) as raised:
                    await uploads.analyze_upload(source, title="Pipeline failure", engine=self.engine)
                self.assertIs(raised.exception, error)
                self.assertTrue(source.file.closed)
                self.assertEqual(list(self.temp_root.iterdir()), [])

    async def test_api_and_embedded_html_reports_match_core_renderers(self) -> None:
        for provider in ("aws", "gcp", "azure"):
            fixture = FIXTURES_DIR / provider / f"sample_{provider}_plan.json"
            title = f"{provider} <report> & review"
            expected_result = TfStride().analyze_plan(fixture, title=title)
            expected_result.analyzed_path = fixture.name
            expected_payload = build_json_report_payload(expected_result)
            expected_markdown = render_markdown(expected_result)

            for endpoint in ("/api/analyze", "/analyze"):
                with self.subTest(provider=provider, endpoint=endpoint):
                    response = await self.client.post(
                        endpoint,
                        data={"title": title},
                        files={"plan": (f"nested/{fixture.name}", fixture.read_bytes(), "application/json")},
                    )

                    self.assertEqual(response.status_code, 200)
                    self.assertNotIn(str(self.temp_root), response.text)
                    if endpoint == "/api/analyze":
                        self.assertEqual(response.headers["content-type"], "application/json")
                        self.assertEqual(response.json(), expected_payload)
                    else:
                        self.assertIn("text/html", response.headers["content-type"])
                        blocks = re.findall(
                            r'<pre class="code-block raw-output-block"><code>(.*?)</code></pre>',
                            response.text,
                            re.DOTALL,
                        )
                        self.assertEqual(len(blocks), 2)
                        self.assertEqual(json.loads(unescape(blocks[0])), expected_payload)
                        self.assertEqual(unescape(blocks[1]), expected_markdown)
                        self.assertNotIn(title, response.text)

    async def test_file_limit_returns_400_in_both_response_formats(self) -> None:
        data = b" " * (uploads.MAX_UPLOAD_BYTES + 1)
        for endpoint in ("/api/analyze", "/analyze"):
            with self.subTest(endpoint=endpoint), mock.patch.object(self.engine, "analyze_plan") as analyze:
                response = await self.client.post(
                    endpoint,
                    files={"plan": ("oversized.json", data, "application/json")},
                )

                self.assertEqual(response.status_code, 400)
                message = "Uploaded plan exceeds the 10 MiB dashboard limit."
                if endpoint == "/api/analyze":
                    self.assertEqual(response.json(), {"kind": "tfstride-error", "message": message})
                else:
                    self.assertIn(message, response.text)
                analyze.assert_not_called()

    async def test_multipart_body_at_limit_is_accepted(self) -> None:
        body = _MULTIPART_PREFIX + _MINIMAL_PLAN + _MULTIPART_SUFFIX
        with mock.patch.object(uploads, "MAX_MULTIPART_REQUEST_BYTES", len(body)):
            response = await self.client.post(
                "/api/analyze",
                content=body,
                headers={"content-type": f"multipart/form-data; boundary={_MULTIPART_BOUNDARY}"},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["analyzed_file"], "plan.json")

    async def test_multipart_overflow_stops_stream_and_currently_returns_parser_error(self) -> None:
        chunks = (_MULTIPART_PREFIX, b" " * 20, b" " * 20, _MULTIPART_SUFFIX)
        for endpoint in ("/api/analyze", "/analyze"):
            for content_length in (None, "1"):
                with self.subTest(endpoint=endpoint, content_length=content_length):
                    consumed: list[int] = []

                    async def body(recorded: list[int]) -> AsyncIterator[bytes]:
                        for index, chunk in enumerate(chunks):
                            recorded.append(index)
                            yield chunk

                    headers = {"content-type": f"multipart/form-data; boundary={_MULTIPART_BOUNDARY}"}
                    if content_length is not None:
                        headers["content-length"] = content_length
                    with (
                        mock.patch.object(uploads, "MAX_MULTIPART_REQUEST_BYTES", len(_MULTIPART_PREFIX) + 20),
                        mock.patch.object(self.engine, "analyze_plan") as analyze,
                    ):
                        response = await self.client.post(endpoint, content=body(consumed), headers=headers)

                    # FastAPI catches the receive() exception while parsing multipart data,
                    # before the middleware's outer handler can turn it into a 413 response.
                    self.assertEqual(response.status_code, 400)
                    self.assertEqual(response.headers["content-type"], "application/json")
                    self.assertEqual(response.json(), {"detail": "There was an error parsing the body"})
                    self.assertEqual(consumed, [0, 1, 2])
                    analyze.assert_not_called()

    async def test_multipart_middleware_returns_413_when_overflow_reaches_its_handler(self) -> None:
        async def consume_request(_scope: Scope, receive: Receive, send: Send) -> None:
            while (await receive()).get("more_body", False):
                pass
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"accepted"})

        def render_limit(
            _request: Request, template_name: str, context: dict[str, object], *, status_code: int = 200
        ) -> HTMLResponse:
            self.assertEqual(template_name, "index.html")
            return HTMLResponse(str(context["error"]), status_code=status_code)

        middleware = uploads.UploadSizeLimitMiddleware(consume_request, template_response=render_limit)
        async with AsyncClient(transport=ASGITransport(app=middleware), base_url="http://testserver") as client:
            for endpoint in ("/api/analyze", "/analyze"):
                with self.subTest(endpoint=endpoint), mock.patch.object(uploads, "MAX_MULTIPART_REQUEST_BYTES", 3):
                    response = await client.post(endpoint, content=b"1234")

                    self.assertEqual(response.status_code, 413)
                    message = "Uploaded plan exceeds the 10 MiB dashboard limit."
                    if endpoint == "/api/analyze":
                        self.assertEqual(response.json(), {"kind": "tfstride-error", "message": message})
                    else:
                        self.assertIn("text/html", response.headers["content-type"])
                        self.assertIn(message, response.text)

    async def test_missing_plan_returns_422_without_analysis(self) -> None:
        for endpoint in ("/api/analyze", "/analyze"):
            with self.subTest(endpoint=endpoint), mock.patch.object(self.engine, "analyze_plan") as analyze:
                response = await self.client.post(endpoint, data={"title": "Missing upload"})

                self.assertEqual(response.status_code, 422)
                self.assertEqual(response.json()["detail"][0]["loc"], ["body", "plan"])
                analyze.assert_not_called()

    async def test_unexpected_pipeline_errors_return_generic_500_after_cleanup(self) -> None:
        for endpoint in ("/api/analyze", "/analyze"):
            for target, name in ((self.engine, "analyze_plan"), (uploads, "render_markdown")):
                with self.subTest(endpoint=endpoint, stage=name):
                    with mock.patch.object(target, name, side_effect=RuntimeError("PRIVATE-ERROR-DETAIL")):
                        response = await self.client.post(
                            endpoint,
                            files={"plan": ("plan.json", _MINIMAL_PLAN, "application/json")},
                        )

                    self.assertEqual(response.status_code, 500)
                    self.assertEqual(response.text, "Internal Server Error")
                    self.assertEqual(list(self.temp_root.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
