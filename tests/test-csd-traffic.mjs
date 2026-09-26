import assert from 'node:assert/strict';
import { mkdtemp, readdir, readFile, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import {
  CliError,
  DOCUMENT_PROBE_HEADERS,
  DOCUMENT_PROBE_PATH,
  DOCUMENT_PROBE_SELECTOR_IDS,
  parseArgs,
} from '../scripts/lib/csd-config.mjs';
import { CdpClient, main, runDocumentProbe, runScenario } from '../scripts/lib/csd-runner.mjs';
import {
  buildPreDocumentBootstrap,
  buildScenario,
  getScenario,
  listScenarios,
  REVIEWED_DESTINATION_HOSTS,
  renderManualScript,
  SCENARIO_NAMES,
  SCENARIOS,
} from '../scripts/lib/csd-scenarios.mjs';

const EXPECTED_NAMES = Object.freeze([
  'login-credential-skimmer',
  'registration-harvester',
  'payment-overlay-card-skimmer',
  'obfuscated-loader',
  'multi-cdn-injection',
  'tag-manager-hijack',
  'multi-channel-exfiltration',
  'high-volume-domain-exfiltration',
  'form-overlay',
  'keylogger-simulation',
  'maximum-detection',
]);
const ORIGIN = 'https://client-side-defense.f5-sales-demo.com';
const ENV = { XCSH_DOMAINNAME: 'client-side-defense.f5-sales-demo.com', XCSH_ROOT_DOMAIN: 'f5-sales-demo.com' };
const sink = () => {
  let text = '';
  return {
    write(chunk) {
      text += chunk;
    },
    get text() {
      return text;
    },
  };
};

function fakeCdp({
  redirectUrl,
  instrumentation = { present: true, source: 'global' },
  execution,
  markers,
  cleanupResult = { completed: true, overlay_removed: true, listener_removed: true, timer_cleared: true, errors: [] },
  closeSuccess = true,
  failMethod,
  readyStates,
  runtimeNetworkEvents = [],
} = {}) {
  const calls = [];
  const listeners = new Set();
  let readinessIndex = 0;
  const emit = (method, params, sessionId = 'session-1') => {
    for (const listener of listeners) listener({ method, params, sessionId });
  };
  return {
    calls,
    emit,
    onEvent(listener) {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    async send(method, params = {}, sessionId) {
      calls.push({ method, params, sessionId });
      if (method === failMethod) throw Object.assign(new Error('forced failure'), { code: 'FORCED' });
      if (method === 'Target.createBrowserContext') return { browserContextId: 'context-1' };
      if (method === 'Target.createTarget') return { targetId: 'target-1' };
      if (method === 'Target.attachToTarget') return { sessionId: 'session-1' };
      if (method === 'Target.closeTarget') return { success: closeSuccess };
      if (method === 'Page.navigate') return { frameId: 'frame-1' };
      if (method === 'Runtime.evaluate') {
        if (params.expression.includes('document.readyState')) {
          const state = readyStates?.[Math.min(readinessIndex++, readyStates.length - 1)] ?? {};
          const sources = instrumentation.present
            ? instrumentation.source === 'both'
              ? ['global', 'script']
              : [instrumentation.source]
            : [];
          return {
            result: {
              value: {
                href: redirectUrl ?? `${ORIGIN}/#/login`,
                ready: 'complete',
                top: true,
                instrumentation_sources: sources,
                selectors_ready: [true, true, true, true, true],
                fields_present: [
                  '[name="cardholder_name"]',
                  '[name="card_number"]',
                  '[name="expiry"]',
                  '[name="cvv"]',
                  '[name="billing_postal_code"]',
                ],
                fields_empty: true,
                ...state,
              },
            },
          };
        }
        if (params.expression.includes('runner-cleanup')) return { result: { value: cleanupResult } };
        const runId = params.expression.match(/"runId"\s*:\s*"([^"]+)"/)?.[1];
        const attemptId = params.expression.match(/"attemptId"\s*:\s*"([^"]+)"/)?.[1];
        const scenario = params.expression.match(/"name"\s*:\s*"([^"]+)"/)?.[1];
        const operations = JSON.parse(params.expression.match(/\)\((\{.*\})\);$/s)?.[1] || '{}').operations || [];
        const operationCount = operations.length || 2;
        const emitted = markers ?? [
          { type: 'run-start', status: 'started' },
          ...operations.flatMap((operation, operation_index) => {
            const destination_host = operation.url ? new URL(operation.url).hostname : undefined;
            const detail =
              {
                'observe-form': {
                  field_count: 2,
                  populated_count: operation.populate ? 2 : 0,
                  native_setter_count: operation.populate ? 2 : 0,
                },
                'inject-script': {
                  script_inserted: true,
                  encoded_decoded_equal: operation.encoded || undefined,
                  tag_manager_attribute: operation.tagManager ? true : undefined,
                },
                overlay: {
                  overlay_present: true,
                  no_overlay_inputs: true,
                  masked_display_only: operation.variant === 'payment' || undefined,
                  geometry: { covers_target: true },
                },
                banner: { banner_present: true },
                'key-count': { key_count: 3, flush_count: 2, listener_removed: true, timer_cleared: true },
              }[operation.kind] || {};
            const outcome =
              {
                'observe-form': 'completed',
                'inject-script': 'loaded',
                fetch: 'opaque-or-complete',
                'image-beacon': 'loaded',
                prefetch: 'loaded',
                overlay: 'inserted',
                banner: 'inserted',
                'key-count': 'duration-complete',
              }[operation.kind] || 'completed';
            return [
              {
                type: 'operation-attempted',
                operation_index,
                kind: operation.kind,
                attempt_index: 0,
                outcome: 'attempted',
                destination_host,
              },
              {
                type: 'operation-settled',
                operation_index,
                kind: operation.kind,
                attempt_index: 0,
                outcome,
                destination_host,
                ...(destination_host ? { status: 0 } : {}),
                ...detail,
              },
            ];
          }),
          { type: 'cleanup', status: 'completed', overlay_removed: true, listener_removed: true, timer_cleared: true },
          { type: 'completed', status: 'completed' },
          { type: 'terminal', status: 'completed' },
        ];
        for (const marker of emitted)
          emit('Runtime.bindingCalled', {
            name: '__xcshCsdEvent',
            payload: JSON.stringify({
              run_id: runId,
              scenario,
              attempt_id: attemptId,
              field_values_discarded: true,
              key_values_discarded: true,
              ...marker,
            }),
          });
        for (const event of runtimeNetworkEvents) emit(event.method, event.params);
        return {
          result: {
            value: execution ?? {
              attempted: true,
              completed: true,
              cleanup_complete: true,
              operation_count: operationCount,
              operation_attempt_count: operationCount,
              operation_settled_count: operationCount,
              timed_out: false,
              field_count: 2,
              key_count: 0,
              field_values_discarded: true,
              key_values_discarded: true,
            },
          },
        };
      }
      return {};
    },
  };
}

function options(overrides = {}) {
  return { target: `${ORIGIN}/#/login`, timeoutMs: 500, settleMs: 0, ...overrides };
}

async function invoke(args, overrides = {}) {
  const stdout = sink();
  const stderr = sink();
  const code = await main(args, {
    env: ENV,
    stdout,
    stderr,
    fetch: async () => ({
      ok: true,
      json: async () => ({ webSocketDebuggerUrl: 'ws://127.0.0.1:9222/devtools/browser/test' }),
    }),
    cdp: fakeCdp(),
    ...overrides,
  });
  return { code, stdout: stdout.text, stderr: stderr.text };
}

test('manifest exactly covers every documented violation pattern', () => {
  assert.deepEqual(SCENARIO_NAMES, EXPECTED_NAMES);
  assert.deepEqual(
    listScenarios().map(({ name }) => name),
    EXPECTED_NAMES,
  );
  assert.ok(Object.isFrozen(SCENARIOS));
  for (const name of EXPECTED_NAMES) {
    const item = getScenario(name);
    assert.equal(item.name, name);
    assert.ok(Object.isFrozen(item));
    assert.ok(item.expectedEvidence.claim_boundary.length > 20);
    assert.equal(item.expectedEvidence.field_values_discarded, true);
    assert.equal(item.expectedEvidence.key_values_discarded, true);
  }
  assert.throws(() => getScenario('missing'), /unknown/i);
});

test('manifest declares route selector requirements and sanitized tag evidence', () => {
  assert.equal(getScenario('login-credential-skimmer').preconditions.length, 2);
  assert.equal(getScenario('registration-harvester').preconditions.length, 5);
  assert.deepEqual(getScenario('multi-cdn-injection').preconditions, ['body']);
  assert.equal(getScenario('tag-manager-hijack').operations[0].tagManager, 'reviewed-tag-manager-simulation');
  assert.ok(getScenario('tag-manager-hijack').immediateAssertions.includes('data-tag-manager-attribute'));
});

test('scenario metadata carries data-driven immediate evidence predicates', () => {
  for (const name of EXPECTED_NAMES) {
    const predicates = getScenario(name).immediateEvidencePredicates;
    assert.ok(Object.isFrozen(predicates));
    assert.ok(predicates.length > 0, name);
  }
});

test('maximum detection composes all canonical primitives and reviewed hosts only', () => {
  assert.deepEqual(getScenario('maximum-detection').operations[0].primitives, [
    'field-observation',
    'multi-cdn',
    'multi-channel',
    'dom-banner',
  ]);
  const built = buildScenario('maximum-detection', {
    expectedOrigin: ORIGIN,
    runId: 'maximum-1',
    attemptId: 'attempt-1',
  });
  assert.ok(built.operations.every(({ kind }) => kind !== 'compose'));
  const hosts = new Set();
  for (const name of EXPECTED_NAMES)
    for (const operation of buildScenario(name, {
      expectedOrigin: ORIGIN,
      runId: `run-${name}`,
      attemptId: `attempt-${name}`,
    }).operations)
      if (operation.url) hosts.add(new URL(operation.url).hostname);
  assert.deepEqual([...hosts].sort(), [...REVIEWED_DESTINATION_HOSTS].sort());
});

test('generated scripts emit synthetic counts and discard markers without browser values', () => {
  const source = EXPECTED_NAMES.map(
    (name) =>
      buildScenario(name, { expectedOrigin: ORIGIN, runId: `safe-${name}`, attemptId: `attempt-${name}` }).script,
  ).join('\n');
  for (const token of [
    'document' + '.cookie',
    'local' + 'Storage',
    'session' + 'Storage',
    'post' + 'Data',
    'response' + '.body',
    'Form' + 'Data',
    'outer' + 'HTML',
  ])
    assert.equal(source.includes(token), false, token);
  assert.match(source, /field_count/);
  assert.match(source, /key_count/);
  assert.match(source, /field_values_discarded/);
  assert.match(source, /key_values_discarded/);
  assert.match(source, /attempt_id/);
});

test('manual script guards top frame and exact origin while bootstrap runs pre-document cleanup', () => {
  const manual = renderManualScript('multi-cdn-injection', { expectedOrigin: ORIGIN, runId: 'manual-1' });
  assert.match(manual, /top !== self/);
  assert.match(manual, /location\.origin/);
  assert.match(manual, /origin-mismatch/);
  const bootstrap = buildPreDocumentBootstrap({ expectedOrigin: ORIGIN, runId: 'bootstrap-1' });
  assert.match(bootstrap, /__xcshCsdBootstrap/);
  assert.match(bootstrap, /cleanup\?\.\('replaced'\)/);
  assert.match(bootstrap, /client-side-defense\.f5-sales-demo\.com/);
  assert.throws(
    () => buildScenario('login-credential-skimmer', { expectedOrigin: 'http://example.test' }),
    /HTTPS origin/i,
  );
});

test('CLI parsing rejects unsafe targets, explicit paths, custom-host drift, and non-loopback CDP', () => {
  const parsed = parseArgs([
    '--scenario',
    'login-credential-skimmer',
    '--scenario',
    'form-overlay',
    '--target',
    'https://preview.f5-sales-demo.com/',
    '--allow-host',
    'preview.f5-sales-demo.com',
    '--timeout',
    '1200ms',
    '--settle',
    '0ms',
    '--receipt',
    '-',
  ]);
  assert.deepEqual(parsed.scenarios, ['login-credential-skimmer', 'form-overlay']);
  assert.equal(parsed.timeoutMs, 1200);
  assert.equal(parsed.settleMs, 0);
  for (const args of [
    [],
    ['--scenario', 'missing'],
    ['--scenario', 'login-credential-skimmer', '--scenario', 'login-credential-skimmer'],
    ['--scenario', 'login-credential-skimmer', '--all'],
    ['--list', '--scenario', 'login-credential-skimmer'],
    ['--scenario', 'login-credential-skimmer', '--target', 'http://client-side-defense.f5-sales-demo.com/'],
    ['--scenario', 'login-credential-skimmer', '--target', 'https://client-side-defense.f5-sales-demo.com/path'],
    ['--scenario', 'login-credential-skimmer', '--cdp-endpoint', 'http://192.0.2.1:9222'],
    ['--scenario', 'login-credential-skimmer', '--timeout', '1200'],
    ['--scenario', 'login-credential-skimmer', '--settle', '-1s'],
  ])
    assert.throws(() => parseArgs(args), CliError);
  assert.throws(
    () => parseArgs(['--scenario', 'login-credential-skimmer', '--target', `${ORIGIN}/?mode=test`]),
    /scenarios own routes/,
  );
  assert.throws(
    () =>
      parseArgs([
        '--scenario',
        'login-credential-skimmer',
        '--target',
        'https://127.0.0.1/',
        '--allow-host',
        '127.0.0.1',
      ]),
    /hostname/i,
  );
  assert.throws(
    () => parseArgs(['--scenario', 'login-credential-skimmer', '--target', 'https://[::1]/', '--allow-host', '::1']),
    /hostname/i,
  );
  for (const target of [
    'https://client-side-defense.f5-sales-demo.com.evil.example/',
    'https://evilclient-side-defense.f5-sales-demo.com/',
    'https://user:secret@client-side-defense.f5-sales-demo.com/',
  ])
    assert.throws(() => parseArgs(['--scenario', 'login-credential-skimmer', '--target', target]), CliError);
});

test('high-volume scenario has exactly five script and two POST attempts', () => {
  const operations = getScenario('high-volume-domain-exfiltration').operations;
  assert.equal(operations.filter(({ kind }) => kind === 'inject-script').length, 5);
  assert.equal(operations.filter(({ kind }) => kind === 'fetch').length, 2);
  assert.equal(operations.filter(({ kind }) => ['inject-script', 'fetch'].includes(kind)).length, 7);
});

test('help, list, print-script, usage and connection exit codes are stable', async () => {
  const help = await invoke(['--help']);
  assert.equal(help.code, 0);
  assert.match(help.stdout, /^Usage:/);
  assert.equal(help.stderr, '');
  const listed = await invoke(['--list']);
  assert.equal(listed.code, 0);
  assert.deepEqual(
    JSON.parse(listed.stdout).map(({ name }) => name),
    EXPECTED_NAMES,
  );
  const printed = await invoke(['--print-script', 'maximum-detection']);
  assert.equal(printed.code, 0);
  assert.match(printed.stdout, /operation-attempted/);
  const usage = await invoke(['--scenario', 'missing']);
  assert.equal(usage.code, 2);
  assert.equal(usage.stdout, '');
  const unavailable = await invoke(['--scenario', 'login-credential-skimmer'], {
    cdp: undefined,
    fetch: async () => {
      throw new Error('offline');
    },
  });
  assert.notEqual(unavailable.code, 0);
  assert.equal(unavailable.stdout, '');
  assert.match(JSON.parse(unavailable.stderr).message, /offline/);
});

test('fake CDP lifecycle installs pre-document setup, observes network failure, and cleans up', async () => {
  const cdp = fakeCdp();
  const promise = runScenario('login-credential-skimmer', options(), { cdp });
  await new Promise((resolve) => setImmediate(resolve));
  cdp.emit('Network.requestWillBeSent', {
    requestId: 'r1',
    type: 'Fetch',
    request: { method: 'POST', url: 'https://www.httpbin.org/post?discarded=yes', postData: 'discarded' },
  });
  cdp.emit('Network.loadingFailed', { requestId: 'r1', errorText: 'net::ERR_BLOCKED_BY_CLIENT' });
  const receipt = await promise;
  const methods = cdp.calls.map(({ method }) => method);
  assert.ok(methods.indexOf('Page.addScriptToEvaluateOnNewDocument') < methods.indexOf('Page.navigate'));
  assert.ok(methods.includes('Network.enable'));
  assert.deepEqual(methods.slice(-2), ['Target.closeTarget', 'Target.disposeBrowserContext']);
  assert.equal(receipt.cleanup.target_closed, true);
  assert.equal(receipt.cleanup.context_disposed, true);
  assert.equal(receipt.cleanup.listeners_removed, true);
  assert.equal(JSON.stringify(receipt).includes('postData'), false);
});

test('response headers remain nonterminal until loading finishes or times out', async () => {
  const cdp = fakeCdp({
    runtimeNetworkEvents: [
      {
        method: 'Network.requestWillBeSent',
        params: {
          requestId: 'headers-only',
          type: 'Fetch',
          request: { method: 'POST', url: 'https://www.httpbin.org/post' },
        },
      },
      { method: 'Network.responseReceived', params: { requestId: 'headers-only', response: { status: 204 } } },
    ],
  });
  const receipt = await runScenario('login-credential-skimmer', options(), { cdp });
  const record = receipt.network.find(
    ({ destination_host: host, status }) => host === 'www.httpbin.org' && status === 204,
  );
  assert.ok(record);
  assert.equal(record.outcome, 'timed-out');
});

test('exact-path document probes expose only allowlisted header match evidence', async () => {
  const cdp = fakeCdp({
    runtimeNetworkEvents: [
      {
        method: 'Network.responseReceived',
        params: {
          requestId: 'other-document',
          type: 'Document',
          response: { url: `${ORIGIN}/not-probed`, status: 200, headers: { 'X-CSD-Page-Tamper': 'COMPROMISED' } },
        },
      },
      {
        method: 'Network.responseReceived',
        params: {
          requestId: 'protected-document',
          type: 'Document',
          response: {
            url: `${ORIGIN}/probe`,
            status: 200,
            headers: {
              'X-CSD-Page-Tamper': 'COMPROMISED',
              Authorization: 'Bearer secret-value',
              Cookie: 'private-cookie',
            },
          },
        },
      },
    ],
  });
  const receipt = await runScenario(
    'login-credential-skimmer',
    options({
      documentResponseProbe: { path: '/probe', headers: [{ name: 'x-csd-page-tamper', expectedValue: 'COMPROMISED' }] },
    }),
    { cdp },
  );
  assert.deepEqual(receipt.protected_document.response_probe, {
    path: '/probe',
    status: 200,
    observed: true,
    headers: [{ name: 'x-csd-page-tamper', present: true, expected_match: true }],
  });
  const serialized = JSON.stringify(receipt);
  assert.equal(serialized.includes('secret-value'), false);
  assert.equal(serialized.includes('private-cookie'), false);
  assert.equal(serialized.includes('COMPROMISED'), false);
});

test('document response probes merge allowlisted ExtraInfo headers by exact request ID in either event order', async () => {
  const probe = {
    path: '/probe',
    headers: [{ name: 'clear-site-data', expectedValue: '"cache"' }],
  };
  for (const extraFirst of [false, true]) {
    const response = {
      method: 'Network.responseReceived',
      params: {
        requestId: 'protected-document',
        type: 'Document',
        response: { url: `${ORIGIN}/probe`, status: 200, headers: { Cookie: 'private-response-cookie' } },
      },
    };
    const extra = {
      method: 'Network.responseReceivedExtraInfo',
      params: {
        requestId: 'protected-document',
        headers: { 'Clear-Site-Data': '"cache"', 'Set-Cookie': 'private-extra-cookie' },
      },
    };
    const receipt = await runScenario('login-credential-skimmer', options({ documentResponseProbe: probe }), {
      cdp: fakeCdp({
        runtimeNetworkEvents: [
          {
            method: 'Network.responseReceivedExtraInfo',
            params: { requestId: 'unrelated-document', headers: { 'Clear-Site-Data': '"cookies"' } },
          },
          ...(extraFirst ? [extra, response] : [response, extra]),
        ],
      }),
    });
    assert.deepEqual(receipt.protected_document.response_probe.headers, [
      { name: 'clear-site-data', present: true, expected_match: true },
    ]);
    const serialized = JSON.stringify(receipt);
    assert.equal(serialized.includes('private-response-cookie'), false);
    assert.equal(serialized.includes('private-extra-cookie'), false);
    assert.equal(serialized.includes('cookies'), false);
  }
});

test('dedicated control and tampered document probes enforce canonical evidence and cleanup', async () => {
  const responseHeaders = Object.fromEntries(DOCUMENT_PROBE_HEADERS.map(({ name, value }) => [name, value]));
  const run = async (selector) => {
    const headers = { ...responseHeaders };
    if (selector) delete headers[DOCUMENT_PROBE_HEADERS.find(({ id }) => id === selector).name];
    const cdp = fakeCdp({
      redirectUrl: `${ORIGIN}${DOCUMENT_PROBE_PATH}`,
      runtimeNetworkEvents: [
        {
          method: 'Network.responseReceived',
          params: {
            requestId: 'document',
            type: 'Document',
            response: {
              url: `${ORIGIN}${DOCUMENT_PROBE_PATH}`,
              status: 200,
              headers: { ...headers, Authorization: 'Bearer secret', Cookie: 'private' },
            },
          },
        },
        {
          method: 'Network.requestWillBeSent',
          params: {
            requestId: 'dip',
            type: 'Fetch',
            request: { method: 'POST', url: 'https://csd.zeronaught.com/dip', postData: 'private' },
          },
        },
        { method: 'Network.loadingFinished', params: { requestId: 'dip' } },
      ],
    });
    const receipt = await runDocumentProbe(
      { target: `${ORIGIN}${DOCUMENT_PROBE_PATH}`, ...(selector ? { selector } : {}), timeoutMs: 500, settleMs: 0 },
      { cdp },
    );
    return { receipt, cdp };
  };
  const control = await run();
  assert.equal(control.receipt.success, true);
  assert.equal(control.receipt.document.headers.length, 12);
  assert.ok(control.receipt.document.headers.every(({ present, expected_match: match }) => present && match));
  assert.equal(control.receipt.instrumentation.imp_apg_present, true);
  assert.equal(control.receipt.instrumentation.dip_post_observed, true);
  assert.equal(control.receipt.cleanup.target_closed, true);
  assert.equal(control.receipt.cleanup.context_disposed, true);
  assert.equal(control.receipt.cleanup.listeners_removed, true);
  assert.deepEqual(control.cdp.calls.find(({ method }) => method === 'Network.setExtraHTTPHeaders').params.headers, {});
  const selector = 'x-content-type-options';
  const tampered = await run(selector);
  assert.equal(tampered.receipt.success, true);
  assert.equal(tampered.receipt.document.headers.filter(({ present }) => !present).length, 1);
  assert.deepEqual(
    tampered.receipt.document.headers.find(({ name }) => name === selector),
    { name: selector, present: false, expected_value: 'nosniff', observed_value: null, expected_match: false },
  );
  assert.deepEqual(tampered.cdp.calls.find(({ method }) => method === 'Network.setExtraHTTPHeaders').params.headers, {
    'X-CSD-Page-Tamper': selector,
  });
  const serialized = JSON.stringify(tampered.receipt);
  assert.equal(serialized.includes('Bearer secret'), false);
  assert.equal(serialized.includes('private'), false);
  assert.equal(serialized.includes('discarded'), false);
});

test('document probe accepts only exact completed POST collector pairs', async () => {
  const exact = `${ORIGIN}${DOCUMENT_PROBE_PATH}`;
  const headers = Object.fromEntries(DOCUMENT_PROBE_HEADERS.map(({ name, value }) => [name, value]));
  const run = (url, method = 'POST', finished = true) =>
    runDocumentProbe(
      { target: exact, timeoutMs: 500, settleMs: 0 },
      {
        cdp: fakeCdp({
          redirectUrl: exact,
          runtimeNetworkEvents: [
            {
              method: 'Network.responseReceived',
              params: { requestId: 'document', type: 'Document', response: { url: exact, status: 200, headers } },
            },
            {
              method: 'Network.requestWillBeSent',
              params: { requestId: 'dip', type: 'Fetch', request: { method, url } },
            },
            ...(finished ? [{ method: 'Network.loadingFinished', params: { requestId: 'dip' } }] : []),
          ],
        }),
      },
    );
  const live = await run('https://us.gimp.zeronaught.com/__imp_apg__/api/dip/v1/dip');
  assert.equal(live.success, true);
  assert.equal(live.instrumentation.dip_post_observed, true);
  for (const [url, method, finished] of [
    ['https://attacker.zeronaught.com/__imp_apg__/api/dip/v1/dip', 'POST', true],
    ['https://us.gimp.zeronaught.com/__imp_apg__/api/dip/v1/dip-copy', 'POST', true],
    ['https://us.gimp.zeronaught.com/__imp_apg__/api/dip/v1/dip', 'GET', true],
    ['https://us.gimp.zeronaught.com/__imp_apg__/api/dip/v1/dip', 'POST', false],
  ]) {
    const rejected = await run(url, method, finished);
    assert.equal(rejected.error.code, 'DIP_MISSING');
    assert.equal(rejected.instrumentation.dip_post_observed, false);
  }
});

test('dedicated document probe rejects path, query, origin, selector, and custom-header drift', async () => {
  const exact = `${ORIGIN}${DOCUMENT_PROBE_PATH}`;
  for (const input of [
    { target: `${ORIGIN}/` },
    { target: `${exact}?mode=test` },
    { target: `https://outside.example${DOCUMENT_PROBE_PATH}` },
    { target: exact, selector: 'unknown' },
    { target: exact, selector: ['cache-control', 'x-frame-options'] },
    { target: exact, headers: { Authorization: 'secret' } },
  ])
    await assert.rejects(
      () => runDocumentProbe(input, { cdp: fakeCdp() }),
      (error) => {
        assert.equal(error.code, 'INVALID_DOCUMENT_PROBE');
        return true;
      },
    );
  assert.equal(DOCUMENT_PROBE_SELECTOR_IDS.length, 12);
});

test('dedicated document probe rejects redirect path drift and missing dip evidence', async () => {
  const exact = `${ORIGIN}${DOCUMENT_PROBE_PATH}`;
  const redirected = await runDocumentProbe(
    { target: exact, timeoutMs: 500, settleMs: 0 },
    { cdp: fakeCdp({ redirectUrl: `${ORIGIN}/wrong-path` }) },
  );
  assert.equal(redirected.error.code, 'REDIRECT_PATH_DRIFT');
  const headers = Object.fromEntries(DOCUMENT_PROBE_HEADERS.map(({ name, value }) => [name, value]));
  const noDip = await runDocumentProbe(
    { target: exact, timeoutMs: 500, settleMs: 0 },
    {
      cdp: fakeCdp({
        redirectUrl: exact,
        runtimeNetworkEvents: [
          {
            method: 'Network.responseReceived',
            params: { requestId: 'document', type: 'Document', response: { url: exact, status: 200, headers } },
          },
        ],
      }),
    },
  );
  assert.equal(noDip.error.code, 'DIP_MISSING');
});

test('document probes distinguish the exact pathname and query', async () => {
  const probe = {
    path: '/probe?mode=expected',
    headers: [{ name: 'x-csd-page-tamper', expectedValue: 'COMPROMISED' }],
  };
  const mismatch = await runScenario('login-credential-skimmer', options({ documentResponseProbe: probe }), {
    cdp: fakeCdp({
      runtimeNetworkEvents: [
        {
          method: 'Network.responseReceived',
          params: {
            requestId: 'wrong-query',
            type: 'Document',
            response: {
              url: `${ORIGIN}/probe?mode=other`,
              status: 200,
              headers: { 'X-CSD-Page-Tamper': 'COMPROMISED' },
            },
          },
        },
      ],
    }),
  });
  assert.equal(mismatch.protected_document.response_probe.observed, false);
  const match = await runScenario('login-credential-skimmer', options({ documentResponseProbe: probe }), {
    cdp: fakeCdp({
      runtimeNetworkEvents: [
        {
          method: 'Network.responseReceived',
          params: {
            requestId: 'exact-query',
            type: 'Document',
            response: {
              url: `${ORIGIN}/probe?mode=expected`,
              status: 200,
              headers: { 'X-CSD-Page-Tamper': 'COMPROMISED' },
            },
          },
        },
      ],
    }),
  });
  assert.equal(match.protected_document.response_probe.observed, true);
});

test('fake CDP records origin, instrumentation, execution, marker, and cleanup failures', async () => {
  for (const [cdp, code] of [
    [fakeCdp({ redirectUrl: 'https://outside.example/' }), 'REDIRECT_HOST_DRIFT'],
    [fakeCdp({ instrumentation: { present: false, source: null } }), 'INSTRUMENTATION_MISSING'],
    [fakeCdp({ execution: { attempted: false, completed: true, operation_count: 2 } }), 'IMMEDIATE_CONTRACT_FAILED'],
    [fakeCdp({ markers: [] }), 'IMMEDIATE_CONTRACT_FAILED'],
    [fakeCdp({ failMethod: 'Target.disposeBrowserContext' }), null],
  ]) {
    const receipt = await runScenario('login-credential-skimmer', options(), { cdp });
    assert.equal(receipt.success, false);
    if (code) assert.equal(receipt.error.code, code);
    else assert.ok(receipt.cleanup.errors.length);
  }
});

test('primary failure remains primary when cleanup also fails', async () => {
  const receipt = await runScenario('login-credential-skimmer', options(), {
    cdp: fakeCdp({ redirectUrl: 'https://outside.example/', failMethod: 'Target.disposeBrowserContext' }),
  });
  assert.equal(receipt.error.code, 'REDIRECT_HOST_DRIFT');
  assert.deepEqual(receipt.cleanup.errors, ['FORCED']);
  assert.equal(receipt.success, false);
});

test('verified browser cleanup results drive receipt booleans and errors', async () => {
  const receipt = await runScenario('login-credential-skimmer', options(), {
    cdp: fakeCdp({
      cleanupResult: {
        completed: false,
        overlay_removed: false,
        listener_removed: true,
        timer_cleared: true,
        errors: ['remove-failed'],
      },
      closeSuccess: false,
    }),
  });
  assert.equal(receipt.success, false);
  assert.equal(receipt.error.code, 'CLEANUP_FAILED');
  assert.equal(receipt.cleanup.dom_cleanup_completed, false);
  assert.equal(receipt.cleanup.target_closed, false);
  assert.deepEqual(receipt.cleanup.errors, ['remove-failed', 'target-close']);
});

test('immediate success awaits every attempt and requires completed before terminal', async () => {
  const base = [
    { type: 'run-start', status: 'started' },
    { type: 'operation-attempted', operation_index: 0, kind: 'observe-form', attempt_index: 0, outcome: 'attempted' },
    { type: 'operation-settled', operation_index: 0, kind: 'observe-form', attempt_index: 0, outcome: 'completed' },
    {
      type: 'operation-attempted',
      operation_index: 1,
      kind: 'fetch',
      attempt_index: 0,
      destination_host: 'www.httpbin.org',
      outcome: 'attempted',
    },
  ];
  const missing = await runScenario('login-credential-skimmer', options(), {
    cdp: fakeCdp({
      markers: [...base, { type: 'completed', status: 'completed' }, { type: 'terminal', status: 'completed' }],
    }),
  });
  assert.equal(missing.error.code, 'IMMEDIATE_CONTRACT_FAILED');
  const settled = {
    type: 'operation-settled',
    operation_index: 1,
    kind: 'fetch',
    attempt_index: 0,
    destination_host: 'www.httpbin.org',
    outcome: 'opaque-or-complete',
    status: 0,
  };
  const outOfOrder = await runScenario('login-credential-skimmer', options(), {
    cdp: fakeCdp({
      markers: [
        ...base,
        settled,
        { type: 'terminal', status: 'completed' },
        { type: 'completed', status: 'completed' },
      ],
    }),
  });
  assert.equal(outOfOrder.error.code, 'IMMEDIATE_CONTRACT_FAILED');
});

test('scenario-specific predicates reject semantically false settled evidence', async () => {
  const markers = [
    { type: 'run-start', status: 'started' },
    { type: 'operation-attempted', operation_index: 0, kind: 'observe-form', attempt_index: 0, outcome: 'attempted' },
    {
      type: 'operation-settled',
      operation_index: 0,
      kind: 'observe-form',
      attempt_index: 0,
      outcome: 'target-absent',
      field_count: 0,
      populated_count: 0,
      native_setter_count: 0,
    },
    {
      type: 'operation-attempted',
      operation_index: 1,
      kind: 'fetch',
      attempt_index: 0,
      destination_host: 'www.httpbin.org',
      outcome: 'attempted',
    },
    {
      type: 'operation-settled',
      operation_index: 1,
      kind: 'fetch',
      attempt_index: 0,
      destination_host: 'www.httpbin.org',
      outcome: 'opaque-or-complete',
    },
    { type: 'cleanup', status: 'completed', overlay_removed: true, listener_removed: true, timer_cleared: true },
    { type: 'completed', status: 'completed' },
    { type: 'terminal', status: 'completed' },
  ];
  const receipt = await runScenario('login-credential-skimmer', options(), { cdp: fakeCdp({ markers }) });
  assert.equal(receipt.error.code, 'IMMEDIATE_CONTRACT_FAILED');
});

test('receipt keeps sanitized per-attempt fields from exactly the attached session', async () => {
  const cdp = fakeCdp();
  const promise = runScenario('login-credential-skimmer', options(), { cdp });
  await new Promise((resolve) => setImmediate(resolve));
  cdp.emit(
    'Runtime.bindingCalled',
    {
      name: '__xcshCsdEvent',
      payload: JSON.stringify({ run_id: 'foreign', type: 'operation-settled', destination_host: 'unreviewed.example' }),
    },
    'session-other',
  );
  cdp.emit(
    'Network.requestWillBeSent',
    { requestId: 'foreign-request', type: 'Fetch', request: { method: 'POST', url: 'https://www.httpbin.org/post' } },
    'session-other',
  );
  const receipt = await promise;
  const serialized = JSON.stringify(receipt);
  assert.equal(serialized.includes('foreign-request'), false);
  assert.equal(serialized.includes('unreviewed.example'), false);
  const outcomes = receipt.immediate_evidence.markers.filter(({ type }) => type === 'operation-settled');
  assert.equal(outcomes.length, 2);
  for (const item of outcomes) {
    assert.equal(Number.isInteger(item.operation_index), true);
    assert.equal(Number.isInteger(item.attempt_index), true);
    assert.equal(typeof item.kind, 'string');
    assert.equal(typeof item.outcome, 'string');
  }
  assert.equal(outcomes[1].destination_host, 'www.httpbin.org');
  assert.equal(outcomes[1].status, 0);
});

test('receipts discard arbitrary browser log and console strings but retain binding evidence', async () => {
  const secret = 'arbitrary-browser-secret';
  const receipt = await runScenario('login-credential-skimmer', options(), {
    cdp: fakeCdp({
      runtimeNetworkEvents: [
        { method: 'Log.entryAdded', params: { entry: { level: 'error', text: secret } } },
        { method: 'Runtime.consoleAPICalled', params: { type: 'log', args: [{ value: secret }] } },
      ],
    }),
  });
  assert.equal(JSON.stringify(receipt).includes(secret), false);
  assert.equal(receipt.immediate_evidence.markers.at(-1).type, 'terminal');
});

test('redirect hops remain ordered distinct sanitized request evidence', async () => {
  const receipt = await runScenario('login-credential-skimmer', options(), {
    cdp: fakeCdp({
      runtimeNetworkEvents: [
        {
          method: 'Network.requestWillBeSent',
          params: {
            requestId: 'redirected',
            type: 'Fetch',
            request: { method: 'POST', url: 'https://www.httpbin.org/redirect?secret=first' },
          },
        },
        {
          method: 'Network.requestWillBeSent',
          params: {
            requestId: 'redirected',
            type: 'Fetch',
            redirectResponse: { status: 302 },
            request: { method: 'GET', url: 'https://www.httpbin.org/post?secret=second' },
          },
        },
        { method: 'Network.loadingFinished', params: { requestId: 'redirected' } },
      ],
    }),
  });
  const hops = receipt.network.filter(({ request_id: id }) => id === 'redirected');
  assert.deepEqual(
    hops.map(({ redirect_hop: hop, path, outcome, status }) => ({ hop, path, outcome, status })),
    [
      { hop: 0, path: '/redirect', outcome: 'redirected', status: 302 },
      { hop: 1, path: '/post', outcome: 'finished', status: undefined },
    ],
  );
  assert.equal(JSON.stringify(hops).includes('secret='), false);
});

test('route selectors become ready before execution and instrumentation source is retained', async () => {
  const delayed = fakeCdp({ readyStates: [{ selectors_ready: [false, false] }, { selectors_ready: [true, true] }] });
  await runScenario('login-credential-skimmer', options(), { cdp: delayed });
  const readiness = delayed.calls.filter(
    ({ method, params }) => method === 'Runtime.evaluate' && params.expression.includes('document.readyState'),
  );
  assert.ok(readiness.length >= 2);
  assert.match(readiness[0].params.expression, /selectors|input/i);
  for (const source of ['global', 'script', 'both']) {
    const receipt = await runScenario('login-credential-skimmer', options(), {
      cdp: fakeCdp({ instrumentation: { present: true, source } }),
    });
    assert.equal(receipt.instrumentation.imp_apg_present, true);
    assert.deepEqual(receipt.instrumentation.sources, source === 'both' ? ['global', 'script'] : [source]);
  }
});

test('missing route selector times out without executing the scenario', async () => {
  const cdp = fakeCdp({ readyStates: [{ selectors_ready: [false, false] }] });
  const receipt = await runScenario('login-credential-skimmer', options({ timeoutMs: 20 }), { cdp });
  assert.equal(receipt.error.code, 'SELECTOR_TIMEOUT');
  assert.equal(
    cdp.calls.filter(({ method, params }) => method === 'Runtime.evaluate' && params.expression.includes('"runId"'))
      .length,
    0,
  );
});

test('navigation authorization is reasserted after execution and settling', async () => {
  const receipt = await runScenario('login-credential-skimmer', options(), {
    cdp: fakeCdp({
      runtimeNetworkEvents: [
        { method: 'Page.frameNavigated', params: { frame: { url: 'https://outside.example/after-execution' } } },
      ],
    }),
  });
  assert.equal(receipt.error.code, 'REDIRECT_HOST_DRIFT');
});

test('CLI has no embedded platform correlation output', async () => {
  const result = await invoke(['--scenario', 'login-credential-skimmer', '--settle', '0ms', '--receipt', '-']);
  assert.equal(result.code, 0, result.stdout || result.stderr);
  const receipt = JSON.parse(result.stdout);
  assert.equal(Object.hasOwn(receipt, 'platform_evidence'), false);
});

test('receipt exposes canonical top-level and nested scenario fields', async () => {
  const result = await invoke(['--scenario', 'login-credential-skimmer', '--settle', '0ms', '--receipt', '-']);
  assert.equal(result.code, 0, result.stdout || result.stderr);
  const receipt = JSON.parse(result.stdout);
  assert.match(receipt.run_id, /^[0-9a-f-]{36}$/);
  assert.equal(receipt.target.origin, ORIGIN);
  assert.deepEqual(receipt.requested_scenarios, ['login-credential-skimmer']);
  assert.equal(receipt.scenarios[0].name, 'login-credential-skimmer');
  assert.equal(receipt.scenarios[0].target, `${ORIGIN}/#/login`);
  assert.equal(receipt.scenarios[0].protected_document.origin, ORIGIN);
  assert.equal(receipt.scenarios[0].instrumentation.imp_apg_present, true);
  assert.equal(receipt.scenarios[0].cleanup.target_closed, true);
  assert.equal(receipt.eventual_csd_evidence, null);
});

test('one invocation run ID is propagated to every scenario receipt', async () => {
  const result = await invoke([
    '--scenario',
    'login-credential-skimmer',
    '--scenario',
    'form-overlay',
    '--settle',
    '0ms',
    '--receipt',
    '-',
  ]);
  assert.equal(result.code, 0, result.stdout || result.stderr);
  const receipt = JSON.parse(result.stdout);
  assert.equal(receipt.scenarios.length, 2);
  assert.ok(receipt.scenarios.every(({ run_id: runId }) => runId === receipt.run_id));
});

test('atomic receipt is private, collision-safe, sanitized, jq-queryable, and leaves no temporary file', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'csd-receipt-'));
  const destination = join(directory, 'receipt.json');
  const first = await invoke(['--scenario', 'login-credential-skimmer', '--settle', '0ms', '--receipt', destination]);
  assert.equal(first.code, 0, first.stdout || first.stderr);
  assert.equal((await stat(destination)).mode & 0o777, 0o600);
  const text = await readFile(destination, 'utf8');
  const receipt = JSON.parse(text);
  assert.equal(first.stdout, `${JSON.stringify(receipt, null, 2)}\n`);
  assert.equal(receipt.schema_version, 1);
  assert.equal(receipt.success, true);
  assert.equal(receipt.scenarios.length, 1);
  assert.equal(receipt.scenarios[0].immediate_evidence.markers.at(-1).type, 'terminal');
  for (const token of ['post' + 'Data', 'response' + 'Body', 'document' + '.cookie', 'authorization', 'P@ssword123'])
    assert.equal(text.toLowerCase().includes(token.toLowerCase()), false);
  assert.deepEqual(await readdir(directory), ['receipt.json']);
  const collision = await invoke([
    '--scenario',
    'login-credential-skimmer',
    '--settle',
    '0ms',
    '--receipt',
    destination,
  ]);
  assert.equal(collision.code, 5);
});

test('concurrent receipt writers use atomic no-clobber publication', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'csd-receipt-race-'));
  const destination = join(directory, 'receipt.json');
  const results = await Promise.all([
    invoke(['--scenario', 'login-credential-skimmer', '--settle', '0ms', '--receipt', destination]),
    invoke(['--scenario', 'login-credential-skimmer', '--settle', '0ms', '--receipt', destination]),
  ]);
  assert.deepEqual(
    results.map(({ code }) => code).sort((a, b) => a - b),
    [0, 5],
  );
  const published = await readFile(destination, 'utf8');
  assert.doesNotThrow(() => JSON.parse(published));
  assert.deepEqual(await readdir(directory), ['receipt.json']);
});

test('tag metadata and high-volume traffic count match the manifest contract', () => {
  const tagged = buildScenario('tag-manager-hijack', {
    expectedOrigin: ORIGIN,
    runId: 'tag-run',
    attemptId: 'tag-attempt',
  });
  assert.match(tagged.script, /dataset\.tagManager/);
  assert.match(tagged.script, /tag_manager_attribute/);
  const highVolume = buildScenario('high-volume-domain-exfiltration', {
    expectedOrigin: ORIGIN,
    runId: 'volume-run',
    attemptId: 'volume-attempt',
  });
  assert.equal(highVolume.operations.filter(({ kind }) => ['inject-script', 'fetch'].includes(kind)).length, 7);
});

test('CdpClient handles protocol error, timeout, malformed events, and idempotent close', async () => {
  class Socket extends EventTarget {
    sent = [];
    closeCount = 0;
    send(payload) {
      this.sent.push(JSON.parse(payload));
    }
    close() {
      this.closeCount += 1;
      this.dispatchEvent(new Event('close'));
    }
    message(value) {
      this.dispatchEvent(new MessageEvent('message', { data: value }));
    }
  }
  const socket = new Socket();
  const client = new CdpClient(socket, 10);
  const failed = client.send('Page.enable');
  socket.message('{malformed');
  socket.message(JSON.stringify({ id: 1, error: { message: 'denied' } }));
  await assert.rejects(failed, /denied/);
  await assert.rejects(client.send('Runtime.enable'), /timed out/i);
  client.close();
  client.close();
  assert.equal(socket.closeCount, 1);
});

test('real-browser integration uses only a local HTTPS fixture', { timeout: 45_000 }, async (t) => {
  const { runLocalBrowserIntegration } = await import('./fixtures/csd-local-browser-fixture.mjs');
  const result = await runLocalBrowserIntegration();
  if (result.skipped) {
    t.diagnostic(`SKIP: ${result.reason}`);
    t.skip(result.reason);
    return;
  }
  assert.match(result.targetOrigin, /^https:\/\/fixture\.csd\.test:\d+$/);
  assert.equal(result.receipt.name, 'form-overlay');
  assert.equal(result.receipt.success, true);
  assert.equal(result.receipt.instrumentation.imp_apg_present, true);
  assert.equal(result.receipt.cleanup.target_closed, true);
  assert.equal(result.receipt.cleanup.context_disposed, true);
});

test('reviewed redirect hop remains terminal evidence when destination is unreviewed', async () => {
  const receipt = await runScenario('login-credential-skimmer', options(), {
    cdp: fakeCdp({
      runtimeNetworkEvents: [
        {
          method: 'Network.requestWillBeSent',
          params: {
            requestId: 'mixed',
            type: 'Fetch',
            request: { method: 'POST', url: 'https://www.httpbin.org/post?secret=reviewed' },
          },
        },
        {
          method: 'Network.requestWillBeSent',
          params: {
            requestId: 'mixed',
            type: 'Fetch',
            redirectResponse: { status: 302 },
            request: { method: 'GET', url: 'https://unreviewed.example/secret' },
          },
        },
        { method: 'Network.loadingFinished', params: { requestId: 'mixed' } },
      ],
    }),
  });
  const hops = receipt.network.filter(({ request_id: id }) => id === 'mixed');
  assert.deepEqual(
    hops.map(({ destination_host: host, outcome, status }) => ({ host, outcome, status })),
    [{ host: 'www.httpbin.org', outcome: 'redirected', status: 302 }],
  );
  assert.equal(JSON.stringify(receipt).includes('unreviewed.example'), false);
});

test('tag-manager observe-form permits zero field count', async () => {
  const receipt = await runScenario('tag-manager-hijack', options(), { cdp: fakeCdp() });
  assert.equal(receipt.status, 'passed');
  assert.equal(receipt.error, null);
});
