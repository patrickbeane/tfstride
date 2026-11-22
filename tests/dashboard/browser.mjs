// Optional real-browser checks. Run with Node 22+ and Chromium; no npm install needed.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';

const project = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const artifacts = await mkdtemp(join(tmpdir(), 'tfstride-workspace-review-'));
const profile = await mkdtemp(join(tmpdir(), 'tfstride-workspace-browser-'));
const children = [];
const pending = new Map();
let socket;
let logs = '';
let commandId = 0;
let stage = 'startup';

async function freePort() {
  const reservation = createServer();
  await new Promise((resolve, reject) => {
    reservation.once('error', reject);
    reservation.listen(0, '127.0.0.1', resolve);
  });
  const port = reservation.address().port;
  await new Promise(resolve => reservation.close(resolve));
  return port;
}

function launch(binary, args) {
  const child = spawn(binary, args, { cwd: project, stdio: ['ignore', 'pipe', 'pipe'] });
  children.push(child);
  child.on('error', error => { logs += `${error.message}\n`; });
  for (const stream of [child.stdout, child.stderr]) {
    stream.on('data', chunk => { logs = (logs + chunk.toString()).slice(-10000); });
  }
  return child;
}

async function waitFor(check, label, timeout = 15000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    try {
      const result = await check();
      if (result) return result;
    } catch { /* Navigation can briefly replace the execution context. */ }
    await delay(50);
  }
  throw new Error(`Timed out: ${label}\n${logs}`);
}

function command(method, params = {}) {
  return new Promise((resolve, reject) => {
    const id = ++commandId;
    const timeout = setTimeout(() => {
      pending.delete(id);
      reject(new Error(`Browser command timed out during ${stage}: ${method} ${params.expression || ''}`));
    }, 15000);
    pending.set(id, { resolve, reject, timeout });
    socket.send(JSON.stringify({ id, method, params }));
  });
}

async function evaluate(expression) {
  const result = await command('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true });
  if (result.exceptionDetails) throw new Error(JSON.stringify(result.exceptionDetails));
  return result.result.value;
}

async function key(key, keyCode) {
  for (const type of ['keyDown', 'keyUp']) {
    await command('Input.dispatchKeyEvent', {
      type, key, code: key, windowsVirtualKeyCode: keyCode,
      ...(type === 'keyDown' && key === 'Enter' ? { text: '\r' } : {}),
    });
  }
}

async function screenshot(name) {
  const { cssContentSize } = await command('Page.getLayoutMetrics');
  const capture = await command('Page.captureScreenshot', {
    format: 'png', captureBeyondViewport: true,
    clip: { x: 0, y: 0, width: cssContentSize.width, height: cssContentSize.height, scale: 1 },
  });
  await writeFile(join(artifacts, name), Buffer.from(capture.data, 'base64'));
}

try {
  const appPort = await freePort();
  const browserPort = await freePort();
  const origin = `http://127.0.0.1:${appPort}`;
  launch(process.env.TFSTRIDE_PYTHON || join(project, '.venv/bin/python'), [
    '-m', 'uvicorn', 'apps.dashboard.main:app', '--host', '127.0.0.1', '--port', String(appPort),
  ]);
  launch(process.env.CHROMIUM_BINARY || 'chromium', [
    '--headless', '--disable-gpu', '--no-first-run', '--no-default-browser-check',
    '--disable-background-networking', '--disable-component-update', '--disable-extensions',
    `--user-data-dir=${profile}`, `--remote-debugging-port=${browserPort}`, 'about:blank',
  ]);
  await waitFor(async () => (await fetch(`${origin}/healthz`)).ok, 'dashboard startup');
  const target = await waitFor(async () => {
    const pages = await (await fetch(`http://127.0.0.1:${browserPort}/json`)).json();
    return pages.find(page => page.type === 'page');
  }, 'Chromium startup');
  socket = new WebSocket(target.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => {
    socket.addEventListener('open', resolve, { once: true });
    socket.addEventListener('error', reject, { once: true });
  });
  const browserErrors = [];
  const submissionStates = [];
  let uploadRequests = 0;
  let fileChoosers = 0;
  socket.addEventListener('message', event => {
    const message = JSON.parse(event.data);
    if (message.method === 'Runtime.exceptionThrown') browserErrors.push(message.params);
    if (message.method === 'Page.fileChooserOpened') fileChoosers += 1;
    if (message.method === 'Runtime.bindingCalled' && message.params.name === 'recordSubmission') {
      submissionStates.push(JSON.parse(message.params.payload));
    }
    if (message.method === 'Network.requestWillBeSent' && message.params.request.method === 'POST'
      && message.params.request.url === `${origin}/analyze`) uploadRequests += 1;
    const request = pending.get(message.id);
    if (!request) return;
    pending.delete(message.id);
    clearTimeout(request.timeout);
    if (message.error) request.reject(new Error(JSON.stringify(message.error)));
    else request.resolve(message.result);
  });
  await command('Page.enable');
  await command('Runtime.enable');
  await command('Runtime.addBinding', { name: 'recordSubmission' });
  await command('Network.enable');
  await command('Page.setInterceptFileChooserDialog', { enabled: true });
  await command('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-reduced-motion', value: 'reduce' }] });

  async function navigate(path) {
    await evaluate('document.documentElement.dataset.navigating = "true"');
    await command('Page.navigate', { url: `${origin}${path}` });
    await waitFor(() => evaluate(`!document.documentElement.dataset.navigating && document.readyState === 'complete' && location.pathname === ${JSON.stringify(path.split('?')[0])}`), path);
    await evaluate('document.fonts.ready.then(() => true)');
  }

  async function viewport(width, height = 900) {
    await command('Emulation.setDeviceMetricsOverride', { width, height, deviceScaleFactor: 1, mobile: false });
  }

  async function selectFile(path) {
    const document = await command('DOM.getDocument');
    const input = await command('DOM.querySelector', { nodeId: document.root.nodeId, selector: '#plan-file' });
    await command('DOM.setFileInputFiles', { nodeId: input.nodeId, files: [path] });
  }

  async function dropFiles(paths, selector = '#upload-dropzone') {
    const point = await evaluate(`(() => {
      const element = document.querySelector(${JSON.stringify(selector)});
      element.scrollIntoView({ block: 'center' });
      const bounds = element.getBoundingClientRect();
      return { x: bounds.x + bounds.width / 2, y: bounds.y + bounds.height / 2 };
    })()`);
    for (const type of ['dragEnter', 'dragOver', 'drop']) {
      await command('Input.dispatchDragEvent', {
        type, ...point, data: { items: [], files: paths, dragOperationsMask: 1 },
      });
    }
  }

  async function ready() {
    await waitFor(() => evaluate('document.getElementById("plan-file-state").textContent.includes("Ready to analyze")'), 'JSON check');
    assert.equal(await evaluate('document.getElementById("analyze-plan").disabled'), false);
  }

  const fixture = join(project, 'fixtures/aws/sample_aws_ecs_fargate_plan.json');
  const badJson = join(artifacts, 'invalid.json');
  const notPlan = join(artifacts, 'not-a-plan.json');
  const emptyFile = join(artifacts, 'empty.json');
  const slowFile = join(artifacts, 'slow.json');
  const readError = join(artifacts, 'unreadable.json');
  const hostileName = 'plan-<img src=x onerror=alert(1)>.json';
  const hostileFile = join(artifacts, hostileName);
  const alternateExtension = join(artifacts, 'plan.txt');
  const minimalPlan = '{"terraform_version":"1.9.0","planned_values":{"root_module":{"resources":[]}}}';
  await Promise.all([
    writeFile(badJson, '{'), writeFile(notPlan, '{}'), writeFile(emptyFile, ''),
    writeFile(slowFile, minimalPlan), writeFile(readError, minimalPlan),
    writeFile(hostileFile, minimalPlan), writeFile(alternateExtension, minimalPlan),
  ]);

  await command('Emulation.setScriptExecutionDisabled', { value: true });
  await viewport(1440);
  await navigate('/');
  await key('Tab', 9);
  assert.equal(await evaluate('document.activeElement.className'), 'skip-link');
  await key('Enter', 13);
  assert.equal(await evaluate('document.activeElement.id'), 'main-content');
  assert.equal(await evaluate('document.querySelector("input[name=plan]").type'), 'file');
  assert.equal(await evaluate('getComputedStyle(document.querySelector("input[name=plan]")).opacity'), '1');
  assert.equal(await evaluate('document.querySelectorAll(".preview-finding").length'), 2);
  await evaluate('document.querySelector(".preview-finding summary").focus()');
  await key('Enter', 13);
  assert(await evaluate('document.querySelector(".preview-finding").open'));
  assert(await evaluate('document.querySelector(".preview-evidence").innerText.includes("secrets-admin")'));
  await key('Enter', 13);
  await evaluate('document.activeElement.blur()');

  for (const width of [1440, 1024, 768, 390, 320]) {
    await viewport(width);
    assert(await evaluate('document.documentElement.scrollWidth <= innerWidth'), `Page overflows at ${width}px`);
    const columns = await evaluate('getComputedStyle(document.querySelector(".analysis-workspace")).gridTemplateColumns.split(" ").length');
    assert.equal(columns, width > 900 ? 2 : 1);
    await screenshot(`workspace-native-${width}.png`);
  }

  // Native keyboard upload and server-side retry remain usable without JavaScript.
  stage = 'native upload';
  await viewport(1440);
  await evaluate('document.getElementById("plan-file").focus()');
  await key('Enter', 13);
  await waitFor(() => fileChoosers === 1, 'native keyboard file chooser');
  await selectFile(badJson);
  await evaluate('document.getElementById("report-title").value = "Native upload review"; document.getElementById("analyze-plan").focus()');
  await key('Enter', 13);
  await waitFor(() => evaluate('location.pathname === "/analyze" && !!document.getElementById("server-error")'), 'native upload error');
  assert.equal(await evaluate('document.getElementById("report-title").value'), 'Native upload review');
  await selectFile(fixture);
  await evaluate('document.getElementById("analyze-plan").focus()');
  await key('Enter', 13);
  await waitFor(() => evaluate('document.querySelector("h1").textContent === "Native upload review"'), 'native upload report');
  assert(await evaluate('document.querySelectorAll(".finding-card").length > 0'));

  // Enhanced upload: selection never submits data and validation never runs the analyzer.
  stage = 'enhanced selection';
  await command('Emulation.setScriptExecutionDisabled', { value: false });
  await navigate('/');
  const requestsBeforeSelection = uploadRequests;
  assert.equal(await evaluate('document.getElementById("plan-upload").dataset.enhanced'), 'true');
  for (const width of [1440, 1024, 768, 390, 320]) {
    await viewport(width);
    assert(await evaluate('document.documentElement.scrollWidth <= innerWidth'), `Enhanced page overflows at ${width}px`);
    await screenshot(`workspace-${width}.png`);
  }
  await viewport(1440);
  await evaluate('document.getElementById("analyze-plan").focus()');
  await key('Enter', 13);
  assert(await evaluate('document.getElementById("upload-error").textContent.includes("Choose a Terraform plan")'));
  assert.equal(await evaluate('document.activeElement.id'), 'plan-file');
  const choosersBefore = fileChoosers;
  await key('Enter', 13);
  await waitFor(() => fileChoosers > choosersBefore, 'enhanced keyboard file chooser');
  await selectFile(fixture);
  await ready();
  assert.equal(await evaluate('document.getElementById("plan-filename").textContent'), 'sample_aws_ecs_fargate_plan.json');
  assert.match(await evaluate('document.getElementById("plan-filesize").textContent'), /[\d.]+ KiB/);
  await screenshot('workspace-selected.png');
  await evaluate('document.getElementById("remove-plan").focus()');
  await key('Enter', 13);
  assert.equal(await evaluate('document.getElementById("plan-file").files.length'), 0);
  assert.equal(await evaluate('document.activeElement.id'), 'plan-file');
  assert(await evaluate('document.getElementById("selected-plan").hidden'));

  for (const [path, message] of [[emptyFile, 'empty'], [badJson, 'not valid JSON']]) {
    await selectFile(path);
    await waitFor(() => evaluate(`document.getElementById("upload-error").textContent.includes(${JSON.stringify(message)})`), message);
    assert.equal(await evaluate('document.getElementById("plan-file").getAttribute("aria-invalid")'), 'true');
    assert(await evaluate('document.getElementById("analyze-plan").disabled'));
  }
  await screenshot('workspace-invalid.png');
  const maxBytes = await evaluate('Number(document.getElementById("plan-upload").dataset.maxUploadBytes)');
  stage = 'size limits and dropping files';
  const oversized = join(artifacts, 'oversized.json');
  const atLimit = join(artifacts, 'at-limit.json');
  await writeFile(oversized, Buffer.alloc(maxBytes + 1, ' '));
  await writeFile(atLimit, minimalPlan.padEnd(maxBytes, ' '));
  await selectFile(oversized);
  assert(await evaluate('document.getElementById("upload-error").textContent.includes("exceeds")'));
  await selectFile(atLimit);
  await ready();
  await dropFiles([fixture, notPlan]);
  assert(await evaluate('document.getElementById("upload-error").textContent.includes("one Terraform plan")'));
  assert.equal(await evaluate('document.getElementById("plan-file").files.length'), 0);
  await dropFiles([alternateExtension]);
  await ready();
  await dropFiles([hostileFile]);
  await ready();
  assert.equal(await evaluate('document.getElementById("plan-filename").textContent'), hostileName);
  assert.equal(await evaluate('document.getElementById("selected-plan").querySelector("img")'), null);
  await dropFiles([fixture], '.site-header');
  assert.equal(await evaluate('location.pathname'), '/');
  assert.equal(await evaluate('document.getElementById("plan-file").files[0].name'), hostileName);
  assert.equal(uploadRequests, requestsBeforeSelection, 'Selecting and checking files must not upload them');

  // Delayed file reads cannot resurrect a removed file or invalidate a newer selection.
  stage = 'delayed file reads';
  await evaluate(`(() => {
    window.originalFileText = File.prototype.text;
    File.prototype.text = function() {
      if (this.name === 'slow.json') return new Promise(resolve => { window.finishSlowRead = resolve; });
      if (this.name === 'unreadable.json') return Promise.reject(new Error('test read failure'));
      return window.originalFileText.call(this);
    };
  })()`);
  await selectFile(slowFile);
  assert(await evaluate('document.getElementById("analyze-plan").disabled'));
  await selectFile(fixture);
  await ready();
  await evaluate('window.finishSlowRead("{")');
  await ready();
  assert(await evaluate('document.getElementById("upload-error").hidden'));
  await selectFile(slowFile);
  await evaluate('document.getElementById("remove-plan").click(); window.finishSlowRead("{}")');
  assert(await evaluate('document.getElementById("selected-plan").hidden'));
  assert.equal(await evaluate('document.getElementById("plan-file").files.length'), 0);
  await selectFile(readError);
  await waitFor(() => evaluate('document.getElementById("upload-error").textContent.includes("could not be read")'), 'file read error');
  await evaluate('File.prototype.text = window.originalFileText');

  // Simulate a browser refusing assignment of a dropped FileList; browsing still recovers.
  stage = 'drop fallback';
  await evaluate('Object.defineProperty(document.getElementById("plan-file"), "files", { configurable: true, get() { return []; }, set() { throw new Error("unsupported"); } })');
  await dropFiles([fixture]);
  assert(await evaluate('document.getElementById("upload-error").textContent.includes("Use browse files")'));
  await evaluate('delete document.getElementById("plan-file").files');
  await dropFiles([fixture]);
  await ready();

  // Record submission state before navigation replaces the document.
  stage = 'submitting';
  await evaluate(`(() => {
    const form = document.getElementById('plan-upload');
    document.getElementById('report-title').value = 'Workspace upload review';
    form.addEventListener('submit', event => {
      recordSubmission(JSON.stringify({
        busy: form.getAttribute('aria-busy'),
        label: document.getElementById('analyze-label').textContent,
        disabled: document.getElementById('analyze-plan').disabled,
        filename: new FormData(form).get('plan').name,
        prevented: event.defaultPrevented,
      }));
    });
  })()`);
  const beforeSubmit = uploadRequests;
  assert(await evaluate(`(() => {
    const form = document.getElementById('plan-upload');
    form.requestSubmit();
    const duplicate = new Event('submit', { bubbles: true, cancelable: true });
    form.dispatchEvent(duplicate);
    return duplicate.defaultPrevented;
  })()`));
  await waitFor(() => evaluate('document.querySelector("h1").textContent === "Workspace upload review"'), 'uploaded report');
  assert.deepEqual(submissionStates[0], {
    busy: 'true', label: 'Analyzing plan…', disabled: true,
    filename: 'sample_aws_ecs_fargate_plan.json', prevented: false,
  });
  assert.equal(submissionStates[1].prevented, true);
  assert.equal(uploadRequests, beforeSubmit + 1);
  assert(await evaluate('document.querySelectorAll(".finding-card").length > 0'));

  stage = 'Back navigation';
  const history = await command('Page.getNavigationHistory');
  await command('Page.navigateToHistoryEntry', { entryId: history.entries[history.currentIndex - 1].id });
  await waitFor(() => evaluate('location.pathname === "/" && !!document.getElementById("plan-upload") && !document.getElementById("analyze-plan").disabled'), 'usable upload after Back');
  assert.equal(await evaluate('document.getElementById("analyze-label").textContent'), 'Analyze plan');
  assert.notEqual(await evaluate('document.getElementById("plan-upload").getAttribute("aria-busy")'), 'true');

  // Valid JSON can still be an invalid Terraform plan: the server owns that decision.
  stage = 'server validation';
  await selectFile(notPlan);
  await ready();
  await evaluate('document.getElementById("report-title").value = "Production <review>"; document.getElementById("analyze-plan").focus()');
  await key('Enter', 13);
  await waitFor(() => evaluate('location.pathname === "/analyze" && !!document.getElementById("server-error")'), 'server validation error');
  assert.equal(await evaluate('document.getElementById("report-title").value'), 'Production <review>');
  await waitFor(() => evaluate('document.activeElement.id === "server-error"'), 'server error focus');
  await screenshot('workspace-server-error.png');
  await selectFile(fixture);
  await ready();
  await evaluate('document.getElementById("analyze-plan").focus()');
  await key('Enter', 13);
  await waitFor(() => evaluate('document.querySelector("h1").textContent === "Production <review>"'), 'corrected report');

  await viewport(1440);
  await navigate('/demo/ecs-fargate');
  assert(await evaluate('document.querySelectorAll(".finding-card").length > 0'));
  await screenshot('report-desktop.png');
  for (const provider of ['aws', 'azure', 'gcp']) {
    await navigate(`/scenarios?provider=${provider}`);
    assert.equal(await evaluate('document.querySelector(".scenario-card").dataset.provider'), provider);
  }
  assert.deepEqual(browserErrors, []);
  console.log(`Browser checks passed. Screenshots: ${artifacts}`);
} finally {
  socket?.close();
  for (const request of pending.values()) clearTimeout(request.timeout);
  await Promise.all(children.map(child => new Promise(resolve => {
    if (child.exitCode !== null) return resolve();
    child.once('close', resolve);
    child.kill('SIGTERM');
    setTimeout(() => { child.kill('SIGKILL'); resolve(); }, 3000).unref();
  })));
  await rm(profile, { recursive: true, force: true });
}
