# Dashboard checks

The Python tests cover routes, the public API/report contract, temporary upload
cleanup, worker isolation, and the landing preview's parity with its existing demo.
Run them with the dashboard and development extras installed:

```bash
.venv/bin/pytest tests/dashboard tests/reporting
.venv/bin/ruff check apps/dashboard tests/dashboard
```

The optional browser checks use Node 22+ and a local Chromium installation. They
require no npm packages and do not add dependencies to the dashboard:

```bash
node --check apps/dashboard/static/workspace.js
node tests/dashboard/browser.mjs
```

The runner starts its own Uvicorn server and headless browser on temporary
loopback ports. It uses `.venv/bin/python` and `chromium` by default; set
`TFSTRIDE_PYTHON` or `CHROMIUM_BINARY` to select other executable paths.
It closes both processes and removes its browser profile when finished. Screenshots
and synthetic test files remain in the printed temporary directory for review.

The browser checks cover:

- Keyboard browsing, skip navigation, and evidence disclosures without JavaScript.
- Native multipart uploads, server errors, preserved report titles, and retries.
- File selection and removal, JSON syntax checks, empty files, and upload size limits.
- Single and multiple file drops, safe filename display, read failures, and stale validation results.
- Submission status, duplicate submission prevention, and browser Back navigation.
- Layouts from 320px to 1440px, reduced-motion preference, and the existing demo/report routes.

The browser only validates file size and JSON syntax. It deliberately accepts
syntactically valid JSON that is not a Terraform plan, leaving the existing server
validator responsible for that error. The preview caches only built-in scenario
data, never uploaded plans.
