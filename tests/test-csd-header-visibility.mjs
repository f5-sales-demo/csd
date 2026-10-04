import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { CLEANUP_GRACE_MS, main, parseArgs, runBoundedPair, TARGET } from '../scripts/csd-header-visibility.mjs';
import { DOCUMENT_PROBE_FIELD_SELECTORS, DOCUMENT_PROBE_HEADERS } from '../scripts/lib/csd-config.mjs';
import { CdpClient, createHeaderVisibilityTracker, runDocumentProbe } from '../scripts/lib/csd-runner.mjs';

const ORIGIN = new URL(TARGET).origin;
const COLLECTOR = 'https://csd.zeronaught.com/dip';
const request = (url = TARGET, extra = {}) => ({
  requestId: 'private-id',
  type: 'Document',
  request: { url, method: 'GET', postData: 'SECRET' },
  ...extra,
});
const emit = (tracker, method, params) => tracker.event(`Network.${method}`, params);
const owned = async () => ({ uid: process.getuid(), isDirectory: () => true, isSymbolicLink: () => false });
const options = { expectedProfile: '/tmp/owned-profile', timeoutMs: 500, settleMs: 0 };
function fakeCdp({
  events = [],
  failMethod,
  missingInstrumentation = false,
  args,
  product,
  closeFailure = false,
} = {}) {
  const listeners = new Set();
  const calls = [];
  let context = 0;
  let session;
  let closes = 0;
  const cdp = {
    calls,
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
        return { sessionId: session };
      }
      if (method === 'Target.closeTarget') return { success: !closeFailure };
      if (method === 'Page.navigate') {
        cdp.emit('Network.requestWillBeSent', request());
        cdp.emit('Network.requestWillBeSentExtraInfo', {
          requestId: 'private-id',
          headers: context === 2 ? { 'X-CSD-Page-Tamper': 'x-content-type-options' } : {},
        });
        cdp.emit('Network.responseReceived', {
          requestId: 'private-id',
          type: 'Document',
          hasExtraInfo: false,
          response: {
            url: TARGET,
            status: 200,
            headers: Object.fromEntries(DOCUMENT_PROBE_HEADERS.map(({ name, value }) => [name, value])),
          },
        });
        cdp.emit('Network.loadingFinished', { requestId: 'private-id' });
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
    emit(t, 'responseReceived', { requestId: 'private-id', hasExtraInfo: true, response: { status: 200 } });
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
  emit(t, 'requestWillBeSent', request(TARGET, { redirectResponse: { status: 302 }, redirectHasExtraInfo: false }));
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
  emit(t, 'requestWillBeSent', request(COLLECTOR, { redirectResponse: { status: 302 }, redirectHasExtraInfo: false }));
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
  const value = await runBoundedPair(options, { cdp, lstat: owned });
  assert.equal(value.success, true);
  assert.equal(cdp.closes, 1);
  assert.equal(cdp.calls.filter(({ method }) => method === 'Target.createBrowserContext').length, 2);
  assert.deepEqual(
    cdp.calls.filter(({ method }) => method === 'Page.navigate').map(({ params }) => params.url),
    [TARGET, TARGET],
  );
  assert.deepEqual(
    cdp.calls.filter(({ method }) => method === 'Network.setExtraHTTPHeaders').map(({ params }) => params.headers),
    [{}, { 'X-CSD-Page-Tamper': 'x-content-type-options' }],
  );
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
    { args: ['--user-data-dir=/wrong'] },
    { product: 'HeadlessChrome/140.0.1.2' },
  ]) {
    const cdp = fakeCdp(input);
    const row = await runBoundedPair(options, { cdp, lstat: owned });
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
  const row = await runBoundedPair(options, { cdp, lstat: owned });
  assert.equal(row.success, false);
  assert.equal(row.observations.length, 2);
  assert.equal(cdp.closes, 1);
  assert.ok(row.observations.every(({ cleanup }) => cleanup.context_disposed && cleanup.listeners_removed));
  assert.doesNotMatch(JSON.stringify(row), /SECRET|evil.test/);
});

test('cleanup failure prevents second navigation', async () => {
  const cdp = fakeCdp({ closeFailure: true });
  const row = await runBoundedPair(options, { cdp, lstat: owned });
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
  const result = spawnSync(process.execPath, ['scripts/csd-header-visibility.mjs', '--help'], {
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
  const row = await runBoundedPair({ ...options, timeoutMs: 20 }, { cdp, lstat: owned });
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
  assert.equal(teardownListeners, 0);
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
  const row = await runBoundedPair(options, { cdp, lstat: owned, signal: AbortSignal.abort() });
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
  const row = await runBoundedPair(options, { cdp, lstat: owned, signal: abort.signal });
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
  const row = await runBoundedPair({ ...options, timeoutMs: 20 }, { cdp, lstat: () => new Promise(() => {}) });
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
  const row = await runBoundedPair({ ...options, timeoutMs: 20 }, { cdp, lstat: owned });
  assert.equal(row.error.code, 'PAIR_TIMEOUT');
  assert.equal(cdp.closes, 1);
});

test('stalled CDP cleanup has separate finite grace and truthful failure', async () => {
  const cdp = fakeCdp();
  const send = cdp.send;
  cdp.send = (method, ...args) => (method === 'Target.closeTarget' ? new Promise(() => {}) : send(method, ...args));
  const started = Date.now();
  const row = await runBoundedPair(options, { cdp, lstat: owned });
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
  const row = await runBoundedPair(options, { cdp, lstat: owned });
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
  const row = await runBoundedPair(parsed, { cdp: fakeCdp(), lstat: owned });
  assert.equal(row.success, true);
  assert.equal(row.observations.length, 2);
  assert.ok(Date.now() - started >= 10000);
  assert.ok(Date.now() - started < 30000);
});
