import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { CLEANUP_GRACE_MS, main, parseArgs, runBoundedPair, TARGET } from '../scripts/csd-header-visibility.mjs';
import { DOCUMENT_PROBE_FIELD_SELECTORS, DOCUMENT_PROBE_HEADERS } from '../scripts/lib/csd-config.mjs';
import {
  CdpClient,
  createHeaderVisibilityTracker,
  runDocumentProbe,
  selectorRequestAllowed,
} from '../scripts/lib/csd-runner.mjs';

const ORIGIN = new URL(TARGET).origin;
const COLLECTOR = 'https://csd.zeronaught.com/dip';
const request = (url = TARGET, extra = {}) => ({
  requestId: 'private-id',
  type: 'Document',
  request: { url, method: 'GET', postData: 'SECRET' },
  ...extra,
});
const emit = (tracker, method, params) =>
  tracker.event(
    `Network.${method}`,
    method === 'responseReceived' ? { ...params, response: { url: TARGET, ...params.response } } : params,
  );
const owned = async () => ({ uid: 1000, mode: 0o40700, isDirectory: () => true, isSymbolicLink: () => false });
const options = { expectedProfile: '/tmp/owned-profile', timeoutMs: 500, settleMs: 0 };
const pairDeps = (cdp, extra = {}) => ({ cdp, lstat: owned, getuid: () => 1000, ...extra });
function fakeCdp({
  events = [],
  failMethod,
  missingInstrumentation = false,
  args,
  product,
  closeFailure = false,
  requestCases = false,
  resumeFailures = 0,
  resumeFault,
  duplicateSelectors = false,
} = {}) {
  const listeners = new Set();
  const calls = [];
  let context = 0;
  let session;
  let closes = 0;
  const sessions = new Map();
  const paused = new Map();
  const resumeAttempts = new Map();
  const wire = [];
  const finish = (item, headers) => {
    wire.push({
      method: item.method,
      collector: item.url === COLLECTOR,
      selector_present: Object.keys(headers).some((name) => name.toLowerCase() === 'x-csd-page-tamper'),
    });
    cdp.emit('Network.requestWillBeSentExtraInfo', { requestId: item.id, headers }, item.sid);
    const responseHeaders = Object.fromEntries(DOCUMENT_PROBE_HEADERS.map(({ name, value }) => [name, value]));
    const selector = Object.entries(headers).find(([key]) => key.toLowerCase() === 'x-csd-page-tamper')?.[1];
    if (selector && item.url === TARGET) {
      const name = DOCUMENT_PROBE_HEADERS.find(({ id }) => id === selector)?.name;
      if (name) delete responseHeaders[name];
    }
    cdp.emit(
      'Network.responseReceived',
      {
        requestId: item.id,
        type: item.type,
        hasExtraInfo: true,
        response: { url: item.url, status: 200, headers: responseHeaders },
      },
      item.sid,
    );
    cdp.emit(
      'Network.responseReceivedExtraInfo',
      { requestId: item.id, statusCode: 200, headers: responseHeaders },
      item.sid,
    );
    cdp.emit('Network.loadingFinished', { requestId: item.id }, item.sid);
  };
  const cdp = {
    calls,
    wire,
    get pausedCount() {
      return paused.size;
    },
    get closes() {
      return closes;
    },
    get listeners() {
      return listeners.size;
    },
    close() {
      closes++;
    },
    onEvent(listener) {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    emit(method, params, sid = session) {
      for (const listener of listeners) listener({ method, params, sessionId: sid });
    },
    async send(method, params = {}, sid) {
      calls.push({ method, params, sessionId: sid });
      if (method === failMethod) throw new Error('SECRET https://evil.test/token?secret');
      if (method === 'Browser.getBrowserCommandLine')
        return {
          arguments: args || [
            '--enable-automation',
            '--remote-debugging-address=127.0.0.1',
            '--user-data-dir=/tmp/owned-profile',
          ],
        };
      if (method === 'Browser.getVersion') return { product: product || 'Chrome/140.0.1.2' };
      if (method === 'Target.createBrowserContext') return { browserContextId: `context-${++context}` };
      if (method === 'Target.createTarget') return { targetId: `target-${context}` };
      if (method === 'Target.attachToTarget') {
        session = `session-${context}`;
        sessions.set(session, { headers: {}, fetch: false });
        return { sessionId: session };
      }
      if (method === 'Target.closeTarget') return { success: !closeFailure };
      if (method === 'Network.setExtraHTTPHeaders') sessions.get(sid).headers = params.headers;
      if (method === 'Fetch.enable') sessions.get(sid).fetch = true;
      if (method === 'Fetch.disable') sessions.get(sid).fetch = false;
      if (method === 'Fetch.continueRequest') {
        const item = paused.get(params.requestId);
        assert.ok(item, 'only diagnostic-owned pauses are resumed');
        const attempt = (resumeAttempts.get(params.requestId) || 0) + 1;
        resumeAttempts.set(params.requestId, attempt);
        if (resumeFailures-- > 0 || resumeFault?.(item, attempt)) throw new Error('SECRET resume failure');
        paused.delete(params.requestId);
        finish(
          item,
          params.headers ? Object.fromEntries(params.headers.map(({ name, value }) => [name, value])) : item.headers,
        );
      }
      if (method === 'Fetch.failRequest') {
        const item = paused.get(params.requestId);
        assert.ok(item);
        assert.equal(params.errorReason, 'Aborted');
        paused.delete(params.requestId);
        cdp.emit('Network.loadingFailed', { requestId: item.id, errorText: 'SECRET' }, item.sid);
      }
      if (method === 'Page.navigate') {
        const cases = [{ url: TARGET, method: 'GET', type: 'Document' }];
        if (requestCases)
          cases.push(
            { url: TARGET, method: 'HEAD', type: 'Fetch' },
            { url: `${ORIGIN}/other-path`, method: 'GET', type: 'Fetch' },
            { url: `${TARGET}?SECRET`, method: 'GET', type: 'Fetch' },
            { url: COLLECTOR, method: 'OPTIONS', type: 'Preflight' },
            { url: COLLECTOR, method: 'POST', type: 'Fetch' },
          );
        for (const [index, item] of cases.entries()) {
          const id = index ? `private-${index}` : 'private-id';
          const headers = { ...sessions.get(sid).headers };
          if (requestCases && index) Object.assign(headers, { 'x-CsD-pAgE-TaMpEr': 'SECRET', Authorization: 'SECRET' });
          if (duplicateSelectors)
            Object.assign(headers, { 'X-CSD-Page-Tamper': 'SECRET', 'x-csd-page-tamper': 'SECRET' });
          cdp.emit(
            'Network.requestWillBeSent',
            request(item.url, {
              requestId: id,
              type: item.type,
              request: { url: item.url, method: item.method, headers, postData: 'SECRET' },
            }),
            sid,
          );
          if (sessions.get(sid).fetch) {
            const fetchId = `private-fetch-${context}-${index}`;
            paused.set(fetchId, { ...item, id, headers, sid });
            cdp.emit(
              'Fetch.requestPaused',
              {
                requestId: fetchId,
                networkId: id,
                resourceType: item.type,
                request: { url: item.url, method: item.method, headers },
              },
              sid,
            );
          } else finish({ ...item, id, sid }, headers);
        }
        for (const event of events) cdp.emit(event.method, event.params, event.sessionId || session);
      }
      if (method === 'Runtime.evaluate')
        return {
          result: {
            value: params.expression.includes('document.readyState')
              ? {
                  href: TARGET,
                  ready: 'complete',
                  top: true,
                  instrumentation_sources: missingInstrumentation ? [] : ['global'],
                  fields_present: DOCUMENT_PROBE_FIELD_SELECTORS,
                  fields_empty: true,
                }
              : true,
          },
        };
      return {};
    },
  };
  return cdp;
}

test('ExtraInfo early and late correlates with identical privacy-safe output', () => {
  const run = (early) => {
    const t = createHeaderVisibilityTracker(ORIGIN);
    const req = {
      requestId: 'private-id',
      headers: { Authorization: 'SECRET', 'x-csd-page-tamper': 'x-content-type-options' },
    };
    const res = {
      requestId: 'private-id',
      statusCode: 201,
      headers: { 'Set-Cookie': 'SECRET', 'X-Content-Type-Options': 'nosniff' },
    };
    if (early) {
      emit(t, 'requestWillBeSentExtraInfo', req);
      emit(t, 'responseReceivedExtraInfo', res);
    }
    emit(
      t,
      'requestWillBeSent',
      request(`${TARGET}?SECRET#SECRET`, {
        initiator: {
          stack: {
            callFrames: [
              {
                url: `${ORIGIN}/app.js?SECRET#SECRET`,
                functionName: 'SECRET',
                lineNumber: 4,
                columnNumber: 2,
              },
            ],
            parent: { SECRET: true },
          },
        },
      }),
    );
    emit(t, 'responseReceived', {
      requestId: 'private-id',
      hasExtraInfo: true,
      response: { url: `${TARGET}?SECRET#SECRET`, status: 200 },
    });
    if (!early) {
      emit(t, 'requestWillBeSentExtraInfo', req);
      emit(t, 'responseReceivedExtraInfo', res);
    }
    emit(t, 'loadingFinished', { requestId: 'private-id' });
    return t.value();
  };
  assert.deepEqual(run(true), run(false));
  const value = run(true);
  assert.deepEqual(value.requests[0].wire_selector, { present: true, exact_match: true });
  assert.deepEqual(value.requests[0].wire_xcto, { present: true, exact_match: true });
  assert.equal(value.requests[0].wire_status, 201);
  assert.equal(value.requests[0].initiator.line, 4);
  assert.doesNotMatch(JSON.stringify(value), /SECRET|private-id|Authorization|Cookie|stack|functionName|postData/);
});

test('redirect hops preserve arrival order and skip explicit false response ExtraInfo hops', () => {
  const t = createHeaderVisibilityTracker(ORIGIN);
  emit(t, 'requestWillBeSent', request(`${ORIGIN}/start`));
  emit(
    t,
    'requestWillBeSent',
    request(TARGET, { redirectResponse: { url: `${ORIGIN}/start`, status: 302 }, redirectHasExtraInfo: false }),
  );
  emit(t, 'responseReceivedExtraInfo', { requestId: 'private-id', statusCode: 200, headers: {} });
  emit(t, 'responseReceived', { requestId: 'private-id', hasExtraInfo: true, response: { status: 200 } });
  for (const headers of [{}, { 'X-CSD-Page-Tamper': 'x-content-type-options' }])
    emit(t, 'requestWillBeSentExtraInfo', { requestId: 'private-id', headers });
  emit(t, 'loadingFinished', { requestId: 'private-id' });
  const [a, b] = t.value().requests;
  assert.deepEqual([a.ordinal, b.ordinal, a.redirect_hop, b.redirect_hop], [1, 2, 0, 1]);
  assert.equal(a.completion, 'redirected');
  assert.equal(a.response_extra_info, 'not-emitted');
  assert.equal(a.wire_xcto, null);
  assert.equal(b.response_extra_info, 'correlated');
  assert.equal(b.wire_xcto.present, false);
  assert.equal(b.wire_selector.present, true);
});

test('partial request FIFO and omitted response flags remain unknown, not false', () => {
  const t = createHeaderVisibilityTracker(ORIGIN);
  emit(t, 'requestWillBeSent', request(`${ORIGIN}/start`));
  emit(t, 'requestWillBeSent', request(TARGET, { redirectResponse: { status: 302 } }));
  emit(t, 'requestWillBeSentExtraInfo', { requestId: 'private-id', headers: {} });
  emit(t, 'responseReceivedExtraInfo', { requestId: 'private-id', statusCode: 200, headers: {} });
  emit(t, 'responseReceived', { requestId: 'private-id', hasExtraInfo: true, response: { status: 200 } });
  for (const row of t.value().requests) {
    assert.equal(row.request_extra_info, 'ambiguous');
    assert.equal(row.wire_selector, null);
    assert.equal(row.wire_xcto, null);
    assert.equal(row.response_extra_info, 'ambiguous');
  }
});

test('missing ExtraInfo remains null and snapshots cannot mutate tracker', () => {
  const t = createHeaderVisibilityTracker(ORIGIN);
  emit(t, 'requestWillBeSent', request());
  const row = t.value().requests[0];
  assert.equal(row.wire_selector, null);
  assert.equal(row.wire_xcto, null);
  assert.equal(row.request_extra_info, 'missing');
  row.path = 'changed';
  assert.equal(t.value().requests[0].path, new URL(TARGET).pathname);
});

test('only HTTPS same origin and exact approved collector origin/path survive', () => {
  const t = createHeaderVisibilityTracker(ORIGIN);
  const urls = [
    TARGET,
    COLLECTOR,
    'https://us.gimp.zeronaught.com/__imp_apg__/api/dip/v1/dip',
    'http://csd.zeronaught.com/dip',
    `${COLLECTOR}/`,
    'https://csd.zeronaught.com:444/dip',
    'https://user:SECRET@csd.zeronaught.com/dip',
    'https://evil.test/dip',
    'data:text/plain,SECRET',
  ];
  urls.forEach((url, i) => {
    emit(t, 'requestWillBeSent', request(url, { requestId: `private-${i}`, initiator: { url: 'not a URL SECRET' } }));
  });
  assert.equal(t.value().requests.length, 3);
  assert.ok(t.value().requests.every(({ initiator }) => initiator === null));
});

test('unscoped redirect hops do not shift scoped ExtraInfo evidence', () => {
  const t = createHeaderVisibilityTracker(ORIGIN);
  emit(t, 'requestWillBeSent', request('https://evil.test/start'));
  emit(t, 'requestWillBeSentExtraInfo', { requestId: 'private-id', headers: {} });
  emit(
    t,
    'requestWillBeSent',
    request(COLLECTOR, {
      redirectResponse: { url: 'https://evil.test/start', status: 302 },
      redirectHasExtraInfo: false,
    }),
  );
  emit(t, 'requestWillBeSentExtraInfo', {
    requestId: 'private-id',
    headers: { 'X-CSD-Page-Tamper': 'x-content-type-options' },
  });
  assert.equal(t.value().requests[0].redirect_hop, 1);
  assert.equal(t.value().requests[0].wire_selector.present, true);
});

test('HTTP non2xx completion is not collector semantic acceptance; failures are enums', () => {
  const t = createHeaderVisibilityTracker(ORIGIN);
  emit(t, 'requestWillBeSent', request(COLLECTOR, { request: { url: COLLECTOR, method: 'POST' } }));
  emit(t, 'responseReceived', {
    requestId: 'private-id',
    hasExtraInfo: false,
    response: { status: 503, fromServiceWorker: true, fromDiskCache: false },
  });
  emit(t, 'loadingFinished', { requestId: 'private-id' });
  assert.equal(t.value().requests[0].status, 503);
  assert.equal(t.value().requests[0].completion, 'finished');
  assert.equal(t.value().collector_semantic_acceptance, 'not-observed');
  emit(t, 'requestServedFromCache', { requestId: 'private-id' });
  emit(t, 'loadingFailed', { requestId: 'private-id', blockedReason: 'SECRET', errorText: 'SECRET' });
  assert.equal(t.value().requests[0].failure, 'blocked');
  assert.equal(t.value().requests[0].served_from_cache, true);
  assert.doesNotMatch(JSON.stringify(t.value()), /SECRET/);
});

test('bounded tracker reports truncation', () => {
  const t = createHeaderVisibilityTracker(ORIGIN);
  for (let i = 0; i < 520; i++) emit(t, 'requestWillBeSent', request(TARGET, { requestId: `private-${i}` }));
  assert.equal(t.value().requests.length, 512);
  assert.equal(t.value().truncated, true);
});

test('opt-in observes missing instrumentation and DIP, filters sessions, cleans up', async () => {
  const cdp = fakeCdp({
    missingInstrumentation: true,
    events: [
      { method: 'Network.requestWillBeSent', params: request(`${ORIGIN}/wrong-session`), sessionId: 'other-session' },
    ],
  });
  const row = await runDocumentProbe({ target: TARGET, timeoutMs: 500, settleMs: 0 }, { cdp, captureMetadata: true });
  assert.equal(row.success, true);
  assert.equal(row.instrumentation.imp_apg_present, false);
  assert.equal(row.metadata_visibility.requests.length, 1);
  assert.deepEqual(row.cleanup, {
    target_closed: true,
    context_disposed: true,
    listeners_removed: true,
    failed: false,
  });
  assert.equal(cdp.listeners, 0);
  assert.deepEqual(
    cdp.calls.slice(-2).map(({ method }) => method),
    ['Target.closeTarget', 'Target.disposeBrowserContext'],
  );
});

test('default document probe shape unchanged and rejects metadata as input key', async () => {
  const row = await runDocumentProbe({ target: TARGET, timeoutMs: 500, settleMs: 0 }, { cdp: fakeCdp() });
  assert.deepEqual(Object.keys(row), [
    'schema_version',
    'mode',
    'target',
    'selector',
    'status',
    'error',
    'document',
    'instrumentation',
    'cleanup',
    'success',
  ]);
  assert.equal(row.error.code, 'DIP_MISSING');
  await assert.rejects(runDocumentProbe({ target: TARGET, captureMetadata: true }, { cdp: fakeCdp() }));
});

test('bounded pair uses fresh contexts exactly two navigations and closes client', async () => {
  const cdp = fakeCdp();
  const value = await runBoundedPair(options, { getuid: () => 1000, cdp, lstat: owned });
  assert.equal(value.success, true);
  assert.equal(cdp.closes, 1);
  assert.equal(cdp.calls.filter(({ method }) => method === 'Target.createBrowserContext').length, 2);
  assert.deepEqual(
    cdp.calls.filter(({ method }) => method === 'Page.navigate').map(({ params }) => params.url),
    [TARGET, TARGET],
  );
  assert.equal(cdp.calls.filter(({ method }) => method === 'Fetch.enable').length, 2);
  assert.equal(cdp.calls.filter(({ method }) => method === 'Fetch.disable').length, 2);
  assert.ok(
    cdp.calls
      .filter(({ method }) => method === 'Network.setExtraHTTPHeaders')
      .every(({ params }) => Object.keys(params.headers).length === 0),
  );
  assert.equal(value.requested_scope, 'session');
  assert.equal(value.control_interception, 'matched');
  assert.equal(value.selected_header, 'x-content-type-options');
  assert.equal(value.schema_acceptance, 'UNKNOWN');
  assert.ok(Number.isFinite(Date.parse(value.started_at)));
  assert.ok(Date.parse(value.ended_at) >= Date.parse(value.started_at));
  assert.deepEqual(
    value.observations.map(({ selector }) => selector),
    [null, 'x-content-type-options'],
  );
  assert.doesNotMatch(JSON.stringify(value), /private-id|owned-profile|"arguments"|Chrome\//);
});

test('provenance rejects headless, unsafe sandbox, wrong profile and product before navigation', async () => {
  for (const input of [
    { args: ['--headless'] },
    { args: ['--no-sandbox'] },
    ...[
      '--ignore-certificate-errors',
      '--ignore-certificate-errors-spki-list=SECRET',
      '--allow-insecure-localhost',
      '--disable-web-security',
      '--allow-running-insecure-content',
      '--disable-features=IsolateOrigins',
    ].map((flag) => ({
      args: ['--enable-automation', '--remote-debugging-address=127.0.0.1', '--user-data-dir=/tmp/owned-profile', flag],
    })),
    { args: ['--user-data-dir=/wrong'] },
    { product: 'HeadlessChrome/140.0.1.2' },
  ]) {
    const cdp = fakeCdp(input);
    const row = await runBoundedPair(options, { getuid: () => 1000, cdp, lstat: owned });
    assert.equal(row.error.code, 'BROWSER_PROVENANCE_FAILED');
    assert.equal(cdp.closes, 1);
    assert.equal(
      cdp.calls.some(({ method }) => method === 'Page.navigate'),
      false,
    );
  }
});

test('navigation failure is sanitized and still disposes context and client', async () => {
  const cdp = fakeCdp({ failMethod: 'Page.navigate' });
  const row = await runBoundedPair(options, { getuid: () => 1000, cdp, lstat: owned });
  assert.equal(row.success, false);
  assert.equal(row.observations.length, 1);
  assert.equal(cdp.closes, 1);
  assert.ok(row.observations.every(({ cleanup }) => cleanup.context_disposed && cleanup.listeners_removed));
  assert.doesNotMatch(JSON.stringify(row), /SECRET|evil.test/);
});

test('cleanup failure prevents second navigation', async () => {
  const cdp = fakeCdp({ closeFailure: true });
  const row = await runBoundedPair(options, { getuid: () => 1000, cdp, lstat: owned });
  assert.equal(row.observations.length, 1);
  assert.equal(row.success, false);
  assert.equal(cdp.closes, 1);
});

test('CLI bounds and loopback reject unsafe values and canonical help executes', () => {
  const base = ['--cdp-endpoint', 'http://127.0.0.1:9222', '--expected-profile', '/tmp/owned-profile'];
  assert.equal(parseArgs(base).timeoutMs, 30000);
  for (const args of [
    base.concat('--timeout-ms', '30001'),
    base.concat('--settle-ms', '15001'),
    base.concat('--timeout-ms', 'NaN'),
    base.concat('--settle-ms', '-1'),
    ['--cdp-endpoint', 'http://evil.test:9222', '--expected-profile', '/tmp/owned-profile'],
    base.concat('--target', TARGET),
  ])
    assert.throws(() => parseArgs(args));
  const cli = fileURLToPath(import.meta.resolve('../scripts/csd-header-visibility.mjs'));
  const result = spawnSync(process.execPath, [cli, '--help'], {
    cwd: new URL('../', import.meta.url),
    encoding: 'utf8',
  });
  assert.equal(result.status, 0);
  assert.match(result.stdout, /^Usage:/);
});

test('main emits safe errors and removes signal handlers on discovery failure', async () => {
  const before = process.listenerCount('SIGINT');
  let output = '';
  const code = await main(['--cdp-endpoint', 'http://127.0.0.1:9222', '--expected-profile', '/tmp/owned-profile'], {
    stdout: {
      write(value) {
        output += value;
      },
    },
    fetch: async () => {
      throw new Error('SECRET');
    },
  });
  assert.equal(code, 4);
  assert.doesNotMatch(output, /SECRET/);
  assert.match(output, /^XCSH_RESULT /);
  assert.equal(process.listenerCount('SIGINT'), before);
});

test('pair deadline aborts in-flight command and closes client', async () => {
  let closed = false;
  const cdp = {
    close() {
      closed = true;
    },
    send(method, params, session, { signal }) {
      return new Promise((resolve, reject) =>
        signal.addEventListener('abort', () => reject(new Error('SECRET')), { once: true }),
      );
    },
  };
  const started = Date.now();
  const row = await runBoundedPair({ ...options, timeoutMs: 20 }, { getuid: () => 1000, cdp, lstat: owned });
  assert.equal(row.error.code, 'PAIR_TIMEOUT');
  assert.equal(closed, true);
  assert.ok(Date.now() - started < 500);
});

test('main successful path emits one receipt and closes supplied client once', async () => {
  let output = '';
  const cdp = fakeCdp();
  const code = await main(
    ['--cdp-endpoint', 'http://127.0.0.1:9222', '--expected-profile', options.expectedProfile, '--settle-ms', '0'],
    {
      cdp,
      lstat: owned,
      getuid: () => 1000,
      stdout: {
        write(value) {
          output += value;
        },
      },
      fetch: async () => ({
        ok: true,
        json: async () => ({
          webSocketDebuggerUrl: 'ws://127.0.0.1:9222/devtools/browser/private-browser-id',
        }),
      }),
    },
  );
  assert.equal(code, 0);
  assert.equal(cdp.closes, 1);
  assert.equal(output.trim().split('\n').length, 1);
  assert.equal(JSON.parse(output.slice(12)).observations.length, 2);
  assert.doesNotMatch(output, /private-browser-id|private-id|owned-profile/);
});

for (const kind of ['requestWillBeSentExtraInfo', 'responseReceivedExtraInfo']) {
  test(`${kind} overflow invalidates both FIFO correlations`, () => {
    const t = createHeaderVisibilityTracker(ORIGIN);
    for (let i = 0; i < 32; i++) {
      emit(
        t,
        'requestWillBeSent',
        request(
          TARGET,
          i
            ? {
                redirectResponse: { status: 302 },
                redirectHasExtraInfo: true,
              }
            : {},
        ),
      );
      emit(t, 'requestWillBeSentExtraInfo', { requestId: 'private-id', headers: {} });
      emit(t, 'responseReceivedExtraInfo', { requestId: 'private-id', statusCode: 200, headers: {} });
    }
    emit(t, 'responseReceived', { requestId: 'private-id', hasExtraInfo: true, response: { status: 200 } });
    emit(t, kind, { requestId: 'private-id', statusCode: 200, headers: {} });
    const value = t.value();
    assert.equal(value.truncated, true);
    assert.equal(value.requests.length, 32);
    for (const row of value.requests) {
      assert.equal(row.request_extra_info, 'ambiguous');
      assert.equal(row.response_extra_info, 'ambiguous');
      assert.equal(row.wire_selector, null);
      assert.equal(row.wire_xcto, null);
      assert.equal(row.wire_status, null);
    }
  });
}

test('metadata snapshot excludes teardown cancellation and late network events', async () => {
  const cdp = fakeCdp();
  const send = cdp.send;
  let teardownListeners;
  cdp.send = async (method, ...args) => {
    if (method === 'Target.closeTarget') {
      teardownListeners = cdp.listeners;
      cdp.emit('Network.loadingFailed', { requestId: 'private-id', canceled: true, errorText: 'SECRET' });
      cdp.emit('Network.requestWillBeSent', request(`${ORIGIN}/teardown`));
    }
    return send(method, ...args);
  };
  const row = await runDocumentProbe({ target: TARGET, timeoutMs: 500, settleMs: 0 }, { cdp, captureMetadata: true });
  assert.equal(teardownListeners, 1); // Listener stays available for late pauses; frozen metadata excludes teardown.
  assert.equal(row.metadata_visibility.requests.length, 1);
  assert.equal(row.metadata_visibility.requests[0].completion, 'finished');
  assert.equal(row.metadata_visibility.requests[0].failure, null);
});

test('CdpClient rejects pre-aborted send without sending or pending work', async () => {
  let sends = 0;
  const cdp = new CdpClient(
    {
      addEventListener() {},
      send() {
        sends++;
      },
    },
    100,
  );
  await assert.rejects(cdp.send('Browser.getVersion', {}, undefined, { signal: AbortSignal.abort() }), {
    code: 'ABORTED',
  });
  assert.equal(sends, 0);
  assert.equal(cdp.pending.size, 0);
});

test('pair pre-abort invokes no provenance command and still closes client', async () => {
  const cdp = fakeCdp();
  const row = await runBoundedPair(options, { getuid: () => 1000, cdp, lstat: owned, signal: AbortSignal.abort() });
  assert.equal(row.error.code, 'PAIR_TIMEOUT');
  assert.equal(cdp.calls.length, 0);
  assert.equal(cdp.closes, 1);
  assert.equal(row.client_closed, true);
});

test('pair abort between provenance awaits prevents the next command', async () => {
  const cdp = fakeCdp();
  const send = cdp.send;
  const abort = new AbortController();
  cdp.send = async (method, ...args) => {
    const result = await send(method, ...args);
    abort.abort();
    return result;
  };
  const row = await runBoundedPair(options, { getuid: () => 1000, cdp, lstat: owned, signal: abort.signal });
  assert.equal(row.error.code, 'PAIR_TIMEOUT');
  assert.deepEqual(
    cdp.calls.map(({ method }) => method),
    ['Browser.getBrowserCommandLine'],
  );
  assert.equal(cdp.closes, 1);
});

test('pre-aborted settle is rejected even when preceding fake evaluation ignores abort', async () => {
  for (const settleMs of [0, 5000]) {
    const cdp = fakeCdp();
    const send = cdp.send;
    const abort = new AbortController();
    cdp.send = async (method, params, ...args) => {
      const result = await send(method, params, ...args);
      if (method === 'Runtime.evaluate' && params.expression === 'true') abort.abort();
      return result;
    };
    const started = Date.now();
    const row = await runDocumentProbe(
      { target: TARGET, timeoutMs: 500, settleMs },
      { cdp, captureMetadata: true, signal: abort.signal },
    );
    assert.equal(row.error.code, 'ABORTED');
    assert.equal(row.cleanup.failed, false);
    assert.ok(Date.now() - started < 500);
  }
});

test('stalled lstat is deadline bounded and closes client', async () => {
  const cdp = fakeCdp();
  const started = Date.now();
  const row = await runBoundedPair(
    { ...options, timeoutMs: 20 },
    { getuid: () => 1000, cdp, lstat: () => new Promise(() => {}) },
  );
  assert.equal(row.error.code, 'PAIR_TIMEOUT');
  assert.equal(cdp.closes, 1);
  assert.equal(row.client_closed, true);
  assert.equal(
    cdp.calls.some(({ method }) => method === 'Page.navigate'),
    false,
  );
  assert.ok(Date.now() - started < 500);
});

test('deadline racing lstat resolution cannot proceed into navigation', async () => {
  const cdp = fakeCdp();
  const abort = new AbortController();
  const row = await runBoundedPair(options, {
    getuid: () => 1000,
    cdp,
    signal: abort.signal,
    lstat: async () => {
      abort.abort();
      return owned();
    },
  });
  assert.equal(row.error.code, 'PAIR_TIMEOUT');
  assert.equal(
    cdp.calls.some(({ method }) => method === 'Target.createBrowserContext'),
    false,
  );
  assert.equal(cdp.closes, 1);
});

test('stalled provenance ignoring signal is bounded', async () => {
  const cdp = fakeCdp();
  cdp.send = () => new Promise(() => {});
  const row = await runBoundedPair({ ...options, timeoutMs: 20 }, { getuid: () => 1000, cdp, lstat: owned });
  assert.equal(row.error.code, 'PAIR_TIMEOUT');
  assert.equal(cdp.closes, 1);
});

test('stalled CDP cleanup has separate finite grace and truthful failure', async () => {
  const cdp = fakeCdp();
  const send = cdp.send;
  cdp.send = (method, ...args) => (method === 'Target.closeTarget' ? new Promise(() => {}) : send(method, ...args));
  const started = Date.now();
  const row = await runBoundedPair(options, { getuid: () => 1000, cdp, lstat: owned });
  assert.equal(row.observations.length, 1);
  assert.equal(row.observations[0].cleanup.target_closed, false);
  assert.equal(row.observations[0].cleanup.context_disposed, false);
  assert.equal(row.observations[0].cleanup.listeners_removed, true);
  assert.equal(row.observations[0].cleanup.failed, true);
  assert.equal(row.success, false);
  assert.equal(cdp.closes, 1);
  assert.equal(row.timing.cleanup_grace_ms, CLEANUP_GRACE_MS);
  assert.ok(Date.now() - started < CLEANUP_GRACE_MS + 500);
});

test('stalled final client close reports false within finite grace', async () => {
  const cdp = fakeCdp();
  cdp.close = () => new Promise(() => {});
  const started = Date.now();
  const row = await runBoundedPair(options, { getuid: () => 1000, cdp, lstat: owned });
  assert.equal(row.client_closed, false);
  assert.equal(row.success, false);
  assert.equal(row.error.code, 'CLEANUP_FAILED');
  assert.ok(Date.now() - started < CLEANUP_GRACE_MS + 500);
});

test('thirty second observation budget permits two actual five second settles', async () => {
  const parsed = parseArgs([
    '--cdp-endpoint',
    'http://127.0.0.1:9222',
    '--expected-profile',
    options.expectedProfile,
    '--timeout-ms',
    '30000',
    '--settle-ms',
    '5000',
  ]);
  const started = Date.now();
  const row = await runBoundedPair(parsed, pairDeps(fakeCdp()));
  assert.equal(row.success, true);
  assert.equal(row.observations.length, 2);
  assert.ok(Date.now() - started >= 10000);
  assert.ok(Date.now() - started < 30000);
});

test('finite selector, scope, control and strict boolean CLI options', () => {
  const base = ['--cdp-endpoint', 'http://127.0.0.1:9222', '--expected-profile', options.expectedProfile];
  const defaults = parseArgs(base);
  assert.deepEqual(
    [defaults.selector, defaults.scope, defaults.control, defaults.debuggerAttribution],
    ['x-content-type-options', 'session', 'matched', false],
  );
  for (const selector of ['x-content-type-options', 'x-frame-options', 'cache-control'])
    for (const scope of ['session', 'document', 'same-origin'])
      for (const control of ['matched', 'passive']) {
        const row = parseArgs([
          ...base,
          '--selector',
          selector,
          '--scope',
          scope,
          '--control',
          control,
          '--debugger-attribution',
          'true',
        ]);
        assert.deepEqual(
          [row.selector, row.scope, row.control, row.debuggerAttribution],
          [selector, scope, control, true],
        );
      }
  for (const [flag, value] of [
    ['--selector', 'SECRET'],
    ['--selector', 'x-content-type-options,x-frame-options'],
    ['--scope', 'all'],
    ['--control', 'none'],
    ['--debugger-attribution', '1'],
    ['--debugger-attribution', 'TRUE'],
    ['--debugger-attribution', 'yes'],
    ['--ignore-certificate-errors', 'true'],
    ['--no-sandbox', 'true'],
  ]) {
    assert.throws(
      () => parseArgs([...base, flag, value]),
      (error) => {
        assert.doesNotMatch(JSON.stringify({ code: error.code, message: error.message }), /SECRET/);
        return true;
      },
    );
  }
  assert.throws(() => parseArgs([...base, '--artifact', fileURLToPath(new URL('../receipt.json', import.meta.url))]));
});

test('selector scope exact authorized path, method, query, collector and preflight boundaries', () => {
  for (const scope of ['session', 'document', 'same-origin']) {
    assert.equal(selectorRequestAllowed({ url: TARGET, method: 'GET', resourceType: 'Document' }, TARGET, scope), true);
    assert.equal(
      selectorRequestAllowed({ url: TARGET, method: 'HEAD', resourceType: 'Fetch' }, TARGET, scope),
      scope !== 'document',
    );
    assert.equal(
      selectorRequestAllowed({ url: TARGET, method: 'GET', resourceType: 'Fetch' }, TARGET, scope),
      scope !== 'document',
    );
    for (const url of [
      `${TARGET}?SECRET`,
      `${TARGET}#SECRET`,
      `${TARGET}/`,
      `${ORIGIN}/other-path`,
      COLLECTOR,
      `${COLLECTOR}/`,
      `${COLLECTOR}?SECRET`,
    ])
      assert.equal(
        selectorRequestAllowed({ url, method: 'GET', resourceType: 'Document' }, TARGET, scope),
        scope === 'session',
      );
    assert.equal(
      selectorRequestAllowed({ url: COLLECTOR, method: 'POST', resourceType: 'Fetch' }, TARGET, scope),
      scope === 'session',
    );
    for (const resourceType of ['Preflight', 'Fetch'])
      assert.equal(selectorRequestAllowed({ url: COLLECTOR, method: 'OPTIONS', resourceType }, TARGET, scope), false);
    assert.equal(
      selectorRequestAllowed({ url: TARGET, method: 'GET', resourceType: 'Preflight' }, TARGET, scope),
      false,
    );
    for (const url of ['http://evil.test', 'https://user:SECRET@evil.test', 'not a URL SECRET'])
      assert.equal(selectorRequestAllowed({ url, method: 'GET', resourceType: 'Document' }, TARGET, scope), false);
  }
});

test('all frozen headers and scopes use identical matched controls and actual wire projection', async () => {
  for (const selector of ['x-content-type-options', 'x-frame-options', 'cache-control'])
    for (const scope of ['session', 'document', 'same-origin']) {
      const cdp = fakeCdp({ requestCases: true });
      const row = await runBoundedPair({ ...options, selector, scope }, pairDeps(cdp));
      assert.equal(row.success, true);
      assert.equal(cdp.calls.filter(({ method }) => method === 'Page.navigate').length, 2);
      const controls = row.observations[0].metadata_visibility.requests;
      const treatment = row.observations[1].metadata_visibility.requests;
      assert.equal(controls.length, 6);
      assert.ok(controls.every(({ wire_selector }) => wire_selector?.present === false));
      const expected = [
        true,
        scope !== 'document',
        scope === 'session',
        scope === 'session',
        false,
        scope === 'session',
      ];
      assert.deepEqual(
        treatment.map(({ wire_selector }) => wire_selector?.present),
        expected,
      );
      assert.ok(
        treatment
          .filter(({ wire_selector }) => wire_selector?.present)
          .every(({ wire_selector }) => wire_selector.exact_match),
      );
      assert.deepEqual(controls[0].wire_selected_header, { present: true, exact_match: true });
      assert.deepEqual(treatment[0].wire_selected_header, { present: false, exact_match: false });
      const enables = cdp.calls.filter(({ method }) => method === 'Fetch.enable');
      assert.deepEqual(enables[0].params, enables[1].params);
      assert.ok(enables.every(({ sessionId }) => /^session-/.test(sessionId)));
      assert.ok(
        cdp.calls
          .filter(({ method }) => method === 'Fetch.continueRequest')
          .every(
            ({ params }) => params.headers.filter(({ name }) => name.toLowerCase() === 'x-csd-page-tamper').length <= 1,
          ),
      );
      for (const [index, sid] of ['session-1', 'session-2'].entries()) {
        const disabled = cdp.calls.findIndex(
          ({ method, sessionId }) => method === 'Fetch.disable' && sessionId === sid,
        );
        const closed = cdp.calls.findIndex(
          ({ method, params }) => method === 'Target.closeTarget' && params.targetId === `target-${index + 1}`,
        );
        assert.ok(disabled >= 0 && disabled < closed);
      }
      assert.doesNotMatch(JSON.stringify(row), /SECRET|Authorization|private-fetch|postData/);
    }
});

test('passive control has exactly two visits and only treatment interception', async () => {
  const cdp = fakeCdp();
  const row = await runBoundedPair({ ...options, control: 'passive', scope: 'document' }, pairDeps(cdp));
  assert.equal(row.success, true);
  assert.equal(row.control_interception, 'passive');
  assert.equal(cdp.calls.filter(({ method }) => method === 'Page.navigate').length, 2);
  assert.deepEqual(
    cdp.calls.filter(({ method }) => method === 'Fetch.enable').map(({ sessionId }) => sessionId),
    ['session-2'],
  );
});

test('resume faults retry or fail safely without selector leakage or a second observation', async () => {
  for (const resumeFailures of [1, 20]) {
    const cdp = fakeCdp({ requestCases: true, resumeFailures });
    const row = await runBoundedPair({ ...options, scope: 'document' }, pairDeps(cdp));
    const resumes = cdp.calls.filter(({ method }) => method === 'Fetch.continueRequest');
    assert.ok(resumes.length > 1);
    if (resumeFailures === 20) {
      assert.equal(row.success, false);
      assert.equal(row.observations.length, 1);
    }
    assert.equal(cdp.closes, 1);
    assert.ok(cdp.calls.some(({ method }) => method === 'Fetch.disable'));
    assert.doesNotMatch(JSON.stringify(row), /SECRET|resume failure/);
  }
});

test('excluded HEAD and collector faults retry stripped headers or abort, never originals', async () => {
  for (const method of ['HEAD', 'POST'])
    for (const failures of [1, 2]) {
      const cdp = fakeCdp({
        requestCases: true,
        duplicateSelectors: true,
        resumeFault: (item, attempt) => item.method === method && attempt <= failures,
      });
      const row = await runBoundedPair({ ...options, scope: 'document' }, pairDeps(cdp));
      assert.equal(row.success, false);
      assert.equal(row.observations.length, 1, 'resumeFailed prevents the treatment visit');
      const resumes = cdp.calls.filter(({ method: name }) => name === 'Fetch.continueRequest');
      assert.ok(resumes.every(({ params }) => Array.isArray(params.headers)));
      assert.ok(
        resumes.every(({ params }) => params.headers.every(({ name }) => name.toLowerCase() !== 'x-csd-page-tamper')),
      );
      const aborts = cdp.calls.filter(({ method: name }) => name === 'Fetch.failRequest');
      assert.equal(aborts.length, failures === 2 ? 1 : 0);
      assert.ok(cdp.wire.every(({ selector_present }) => !selector_present));
      assert.equal(cdp.wire.filter((item) => item.method === method).length, failures === 1 ? 1 : 0);
      assert.equal(cdp.pausedCount, 0);
      assert.equal(cdp.listeners, 0);
      assert.equal(cdp.closes, 1);
      assert.ok(cdp.calls.some(({ method: name }) => name === 'Fetch.disable'));
      assert.doesNotMatch(JSON.stringify(row), /SECRET|private-fetch|Authorization|resume failure/);
    }
});

test('treatment retry removes intended selector instead of restoring original case variants', async () => {
  const cdp = fakeCdp({
    duplicateSelectors: true,
    resumeFault: (item, attempt) => item.sid === 'session-2' && attempt === 1,
  });
  const row = await runBoundedPair({ ...options, scope: 'document' }, pairDeps(cdp));
  assert.equal(row.success, false);
  assert.equal(row.observations.length, 2);
  const resumes = cdp.calls.filter(
    ({ method, sessionId }) => method === 'Fetch.continueRequest' && sessionId === 'session-2',
  );
  assert.equal(resumes.length, 2);
  assert.equal(resumes[0].params.headers.filter(({ name }) => name.toLowerCase() === 'x-csd-page-tamper').length, 1);
  assert.ok(resumes[1].params.headers.every(({ name }) => name.toLowerCase() !== 'x-csd-page-tamper'));
  assert.ok(cdp.wire.every(({ selector_present }) => !selector_present));
  assert.equal(cdp.pausedCount, 0);
  assert.equal(cdp.listeners, 0);
  assert.equal(row.observations[1].cleanup.paused_requests_resumed, false);
  assert.doesNotMatch(JSON.stringify(row), /SECRET|private-fetch|resume failure/);
});

test('header construction faults abort closed without any original continuation', async () => {
  const cdp = fakeCdp();
  const send = cdp.send.bind(cdp);
  cdp.send = async (method, ...args) => {
    if (method === 'Page.navigate') {
      const headers = {};
      Object.defineProperty(headers, 'x-CsD-pAgE-TaMpEr', {
        enumerable: true,
        get() {
          throw new Error('SECRET');
        },
      });
      cdp.emit('Fetch.requestPaused', {
        requestId: 'private-fault',
        resourceType: 'Document',
        request: { url: TARGET, method: 'GET', headers },
      });
    }
    return send(method, ...args);
  };
  const row = await runBoundedPair({ ...options, scope: 'document' }, pairDeps(cdp));
  assert.equal(row.success, false);
  assert.equal(row.observations.length, 1);
  assert.ok(
    cdp.calls.some(
      ({ method, params }) =>
        method === 'Fetch.failRequest' && params.requestId === 'private-fault' && params.errorReason === 'Aborted',
    ),
  );
  assert.ok(
    cdp.calls
      .filter(({ method }) => method === 'Fetch.continueRequest')
      .every(({ params }) => Array.isArray(params.headers)),
  );
  const abortIndex = cdp.calls.findIndex(({ method }) => method === 'Fetch.failRequest');
  const disableIndex = cdp.calls.findIndex(({ method }) => method === 'Fetch.disable');
  assert.ok(abortIndex >= 0 && disableIndex > abortIndex, 'disable is last cleanup after abort attempt');
  assert.equal(cdp.listeners, 0);
  assert.doesNotMatch(JSON.stringify(row), /SECRET|private-fault/);
});

test('selector and XCTO projections share generic UNKNOWN validation', () => {
  for (const headers of [
    undefined,
    null,
    [],
    'SECRET',
    7,
    {
      'X-CSD-Page-Tamper': 'cache-control',
      'x-csd-page-tamper': 'SECRET',
      'X-Content-Type-Options': 'nosniff',
      'x-content-type-options': 'SECRET',
    },
    { 'x-csd-page-tamper': 7, 'x-content-type-options': ['nosniff'] },
  ]) {
    const t = createHeaderVisibilityTracker(ORIGIN);
    emit(t, 'requestWillBeSent', request());
    emit(t, 'requestWillBeSentExtraInfo', { requestId: 'private-id', headers });
    emit(t, 'responseReceived', { requestId: 'private-id', hasExtraInfo: true, response: { status: 200, headers } });
    emit(t, 'responseReceivedExtraInfo', { requestId: 'private-id', statusCode: 200, headers });
    const row = t.value().requests[0];
    for (const field of [
      'wire_selector',
      'wire_xcto',
      'response_xcto',
      'wire_selected_header',
      'response_selected_header',
    ])
      assert.equal(row[field], null, field);
    assert.doesNotMatch(JSON.stringify(row), /SECRET|nosniff/);
  }
});

test('generic selected header projection requires actual ExtraInfo and unambiguous headers', () => {
  for (const id of ['x-content-type-options', 'x-frame-options', 'cache-control']) {
    const header = DOCUMENT_PROBE_HEADERS.find((header) => header.id === id);
    const t = createHeaderVisibilityTracker(ORIGIN, id);
    emit(t, 'requestWillBeSent', request());
    emit(t, 'responseReceived', {
      requestId: 'private-id',
      hasExtraInfo: true,
      response: { status: 200, headers: { [id]: header.value } },
    });
    assert.equal(t.value().requests[0].wire_selected_header, null);
    assert.deepEqual(t.value().requests[0].response_selected_header, { present: true, exact_match: true });
    emit(t, 'responseReceivedExtraInfo', {
      requestId: 'private-id',
      statusCode: 200,
      headers: { [id.toUpperCase()]: header.value },
    });
    assert.deepEqual(t.value().requests[0].wire_selected_header, { present: true, exact_match: true });
    const ambiguous = createHeaderVisibilityTracker(ORIGIN, id);
    emit(ambiguous, 'requestWillBeSent', request());
    emit(ambiguous, 'responseReceived', { requestId: 'private-id', hasExtraInfo: true, response: { status: 200 } });
    emit(ambiguous, 'responseReceivedExtraInfo', {
      requestId: 'private-id',
      statusCode: 200,
      headers: { [id]: header.value, [id.toUpperCase()]: 'SECRET' },
    });
    assert.equal(ambiguous.value().requests[0].wire_selected_header, null);
    assert.doesNotMatch(JSON.stringify(ambiguous.value()), /SECRET/);
  }
});

test('nonroot and strict 0700 owned profile are required before navigation', async () => {
  for (const extra of [
    { getuid: () => 0 },
    { lstat: async () => ({ ...(await owned()), mode: 0o40755 }) },
    { lstat: async () => ({ ...(await owned()), uid: 2000 }) },
  ]) {
    const cdp = fakeCdp();
    const row = await runBoundedPair(options, pairDeps(cdp, extra));
    assert.equal(row.success, false);
    assert.ok(['NONROOT_REQUIRED', 'PROFILE_NOT_OWNED'].includes(row.error.code));
    assert.equal(cdp.calls.filter(({ method }) => method === 'Page.navigate').length, 0);
    assert.equal(cdp.closes, 1);
  }
});

test('response URL mismatch keeps wire attribution UNKNOWN', () => {
  const t = createHeaderVisibilityTracker(ORIGIN, 'cache-control');
  emit(t, 'requestWillBeSent', request());
  emit(t, 'requestWillBeSentExtraInfo', { requestId: 'private-id', headers: {} });
  emit(t, 'responseReceived', {
    requestId: 'private-id',
    hasExtraInfo: true,
    response: { url: `${TARGET}?SECRET`, status: 200 },
  });
  emit(t, 'responseReceivedExtraInfo', { requestId: 'private-id', statusCode: 200, headers: {} });
  assert.equal(t.value().requests[0].wire_selected_header, null);
  assert.equal(t.value().requests[0].wire_selector, null);
  assert.doesNotMatch(JSON.stringify(t.value()), /SECRET/);
});

test('trusted isolated headed HTTPS fixture exercises browser-generated HEAD and collector preflight', {
  skip: process.env.XCSH_CSD_HEADER_FIXTURE !== '1',
  timeout: 90000,
}, async () => {
  // Prerequisite: this certificate's CA is already trusted by Chrome's system trust store.
  // SANs must cover client-side-defense.f5-sales-demo.com and csd.zeronaught.com.
  // No certificate bypass, system trust mutation, public target, or raw request persistence.
  const { createServer } = await import('node:https');
  const { mkdtemp, readFile, rm, chmod } = await import('node:fs/promises');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');
  const { spawn } = await import('node:child_process');
  assert.ok(process.getuid?.() > 0, 'FIXTURE_NONROOT_REQUIRED');
  for (const name of ['XCSH_CSD_FIXTURE_CHROME', 'XCSH_CSD_FIXTURE_TLS_KEY', 'XCSH_CSD_FIXTURE_TLS_CERT'])
    assert.ok(process.env[name], `FIXTURE_REQUIRED_${name}`);
  const key = await readFile(process.env.XCSH_CSD_FIXTURE_TLS_KEY);
  const cert = await readFile(process.env.XCSH_CSD_FIXTURE_TLS_CERT);
  const facts = [];
  const fields = ['cardholder_name', 'card_number', 'expiry', 'cvv', 'billing_postal_code'];
  const html = `<!doctype html><html><body>${fields.map((name) => `<input name="${name}" value="">`).join('')}<script>
    Promise.allSettled([fetch('/csd-page-tamper/payment', {method:'HEAD'}), fetch('/other-path'),
      fetch('https://csd.zeronaught.com/dip', {method:'POST',headers:{'Content-Type':'application/json'},body:'{}'})])
      .then(() => { document.documentElement.dataset.fixtureComplete = 'true'; });
    </script></body></html>`;
  const server = createServer({ key, cert }, (req, res) => {
    const host = (req.headers.host || '').split(':')[0];
    const payment = host === new URL(TARGET).hostname && req.url === new URL(TARGET).pathname;
    const collector = host === 'csd.zeronaught.com' && req.url === '/dip';
    const other = host === new URL(TARGET).hostname && req.url === '/other-path';
    const selector = req.headers['x-csd-page-tamper'];
    facts.push({
      payment,
      collector,
      other,
      method: req.method,
      selector_present: selector !== undefined,
      selector_exact: ['x-content-type-options', 'x-frame-options', 'cache-control'].includes(selector),
    });
    if (!payment && !collector && !other) {
      res.writeHead(404);
      res.end();
      return;
    }
    const headers = {
      'Content-Type': payment ? 'text/html' : 'application/json',
      'Access-Control-Allow-Origin': ORIGIN,
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'content-type, x-csd-page-tamper',
    };
    for (const { id, name, value } of DOCUMENT_PROBE_HEADERS)
      if (['x-content-type-options', 'x-frame-options', 'cache-control'].includes(id) && !(payment && selector === id))
        headers[name] = value;
    res.writeHead(200, headers);
    res.end(req.method === 'HEAD' || req.method === 'OPTIONS' ? undefined : payment ? html : '{}');
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const port = server.address().port;
  const profile = await mkdtemp(join(tmpdir(), 'csd-headed-fixture-'));
  await chmod(profile, 0o700);
  let chrome;
  try {
    chrome = spawn(
      process.env.XCSH_CSD_FIXTURE_CHROME,
      [
        '--enable-automation',
        '--remote-debugging-address=127.0.0.1',
        '--remote-debugging-port=0',
        `--user-data-dir=${profile}`,
        '--no-first-run',
        '--no-default-browser-check',
        '--no-proxy-server',
        '--disable-background-networking',
        `--host-resolver-rules=MAP client-side-defense.f5-sales-demo.com:443 127.0.0.1:${port}, MAP csd.zeronaught.com:443 127.0.0.1:${port}, MAP * ~NOTFOUND`,
        'about:blank',
      ],
      { stdio: 'ignore' },
    );
    let endpoint;
    for (let attempt = 0; attempt < 100 && !endpoint; attempt++) {
      try {
        const [debugPort] = (await readFile(join(profile, 'DevToolsActivePort'), 'utf8')).split('\n');
        endpoint = `http://127.0.0.1:${debugPort}`;
      } catch {
        await new Promise((resolve) => setTimeout(resolve, 100));
      }
    }
    assert.ok(endpoint, 'FIXTURE_CHROME_DISCOVERY_FAILED');
    for (const selector of ['x-content-type-options', 'x-frame-options', 'cache-control'])
      for (const scope of ['session', 'document', 'same-origin'])
        for (const control of ['matched', 'passive']) {
          facts.length = 0;
          const discovery = await fetch(`${endpoint}/json/version`);
          const { webSocketDebuggerUrl } = await discovery.json();
          const cdp = await CdpClient.connect(webSocketDebuggerUrl, 1000, globalThis.WebSocket);
          const projections = new Map();
          const unsubscribe = cdp.onEvent(({ sessionId, method, params }) => {
            if (!sessionId || !method.startsWith('Network.')) return;
            if (!projections.has(sessionId))
              projections.set(
                sessionId,
                ['x-content-type-options', 'x-frame-options', 'cache-control'].map((id) =>
                  createHeaderVisibilityTracker(ORIGIN, id),
                ),
              );
            for (const tracker of projections.get(sessionId)) tracker.event(method, params);
          });
          const row = await runBoundedPair(
            { expectedProfile: profile, timeoutMs: 30000, settleMs: 1500, selector, scope, control },
            { cdp },
          );
          unsubscribe();
          assert.equal(row.success, true, 'FIXTURE_OBSERVATION_FAILED');
          assert.equal(row.observations.length, 2);
          assert.equal(row.control_interception, control);
          assert.equal(row.client_closed, true);
          for (const observation of row.observations) {
            assert.equal(observation.cleanup.fetch_disabled, true);
            assert.equal(observation.cleanup.paused_requests_resumed, true);
            assert.equal(observation.cleanup.inflight_resume_count, 0);
            assert.equal(observation.cleanup.listeners_removed, true);
            assert.equal(observation.cleanup.target_closed, true);
            assert.equal(observation.cleanup.context_disposed, true);
            assert.equal(observation.cleanup.failed, false);
          }
          const controlRequests = row.observations[0].metadata_visibility.requests;
          const documentRequest = (requests) =>
            requests.find(
              ({ resource_type, path, method }) =>
                resource_type === 'Document' && path === new URL(TARGET).pathname && method === 'GET',
            );
          const baseline = documentRequest(controlRequests);
          assert.deepEqual(baseline?.wire_selector, { present: false, exact_match: false });
          assert.deepEqual(baseline?.wire_selected_header, { present: true, exact_match: true });
          assert.ok(controlRequests.every(({ wire_selector }) => wire_selector?.present === false));
          for (const [index, trackers] of [...projections.values()].entries())
            for (const [headerIndex, tracker] of trackers.entries()) {
              const id = ['x-content-type-options', 'x-frame-options', 'cache-control'][headerIndex];
              const omitted = index === 1 && id === selector;
              assert.deepEqual(
                documentRequest(tracker.value().requests)?.wire_selected_header,
                { present: !omitted, exact_match: !omitted },
                `FIXTURE_FROZEN_${id}`,
              );
            }
          assert.equal(facts.filter(({ payment, method }) => payment && method === 'GET').length, 2);
          assert.equal(facts.filter(({ payment, method }) => payment && method === 'HEAD').length, 2);
          assert.equal(facts.filter(({ collector, method }) => collector && method === 'POST').length, 2);
          assert.ok(facts.some(({ collector, method }) => collector && method === 'OPTIONS'));
          assert.ok(
            facts.filter(({ method }) => method === 'OPTIONS').every(({ selector_present }) => !selector_present),
          );
          const treatment = row.observations[1].metadata_visibility.requests;
          assert.deepEqual(documentRequest(treatment)?.wire_selector, { present: true, exact_match: true });
          assert.deepEqual(documentRequest(treatment)?.wire_selected_header, { present: false, exact_match: false });
          if (scope === 'document') {
            assert.ok(
              treatment
                .filter((item) => item !== documentRequest(treatment))
                .every(({ wire_selector }) => wire_selector?.present === false),
            );
            const documents = facts.filter(({ payment, method }) => payment && method === 'GET');
            assert.deepEqual(
              documents.map(({ selector_present }) => selector_present),
              [false, true],
            );
            assert.equal(documents[1].selector_exact, true);
            assert.ok(
              facts
                .filter((item) => !item.payment || item.method !== 'GET')
                .every(({ selector_present }) => !selector_present),
            );
          }
          const paymentHead = treatment.find(
            ({ path, method }) => path === new URL(TARGET).pathname && method === 'HEAD',
          );
          const dip = treatment.find(({ collector, method }) => collector && method === 'POST');
          assert.equal(paymentHead?.wire_selector?.present, scope !== 'document');
          assert.equal(dip?.wire_selector?.present, scope === 'session');
          assert.doesNotMatch(JSON.stringify(row), /postData|Cookie|Authorization|private-fetch/);
        }
  } finally {
    if (chrome && chrome.exitCode === null) {
      chrome.kill('SIGTERM');
      await Promise.race([
        new Promise((resolve) => chrome.once('exit', resolve)),
        new Promise((resolve) => setTimeout(resolve, 1000)),
      ]);
      if (chrome.exitCode === null) chrome.kill('SIGKILL');
    }
    await new Promise((resolve) => server.close(resolve));
    await rm(profile, { recursive: true, force: true });
  }
});

test('debugger attribution is opt-in and never requests source, stacks, or breakpoints', async () => {
  for (const debuggerAttribution of [false, true]) {
    const cdp = fakeCdp({
      events: [
        {
          method: 'Debugger.scriptParsed',
          params: {
            scriptId: 'SECRET',
            url: `${ORIGIN}/app.js?SECRET`,
            sourceMapURL: 'SECRET',
            executionContextId: 10,
          },
        },
        { method: 'Debugger.scriptParsed', params: { scriptId: 'SECRET', url: 'https://evil.test/SECRET.js' } },
      ],
    });
    const row = await runBoundedPair({ ...options, debuggerAttribution }, pairDeps(cdp));
    assert.equal(row.success, true);
    assert.equal(cdp.calls.filter(({ method }) => method === 'Debugger.enable').length, debuggerAttribution ? 2 : 0);
    assert.ok(
      cdp.calls.every(
        ({ method }) =>
          ![
            'Debugger.getScriptSource',
            'Debugger.setBreakpoint',
            'Debugger.setBreakpointByUrl',
            'Debugger.pause',
            'Debugger.getStackTrace',
          ].includes(method),
      ),
    );
    assert.doesNotMatch(JSON.stringify(row), /SECRET|evil.test|sourceMapURL|scriptId|executionContextId/);
  }
});

test('artifact is a fresh private 0600 receipt and an existing file is not overwritten', async () => {
  const { mkdtemp, stat, readFile, rm } = await import('node:fs/promises');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');
  const directory = await mkdtemp(join(tmpdir(), 'csd-receipt-test-'));
  const artifact = join(directory, 'receipt.json');
  const args = [
    '--cdp-endpoint',
    'http://127.0.0.1:9222',
    '--expected-profile',
    options.expectedProfile,
    '--settle-ms',
    '0',
    '--artifact',
    artifact,
  ];
  const dependencies = () => ({
    ...pairDeps(fakeCdp()),
    stdout: { write() {} },
    fetch: async () => ({
      ok: true,
      json: async () => ({ webSocketDebuggerUrl: 'ws://127.0.0.1:9222/devtools/browser/test' }),
    }),
  });
  try {
    assert.equal(await main(args, dependencies()), 0);
    assert.equal((await stat(artifact)).mode & 0o777, 0o600);
    const original = await readFile(artifact, 'utf8');
    assert.equal(JSON.parse(original).observations.length, 2);
    assert.equal(await main(args, dependencies()), 4);
    assert.equal(await readFile(artifact, 'utf8'), original);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
