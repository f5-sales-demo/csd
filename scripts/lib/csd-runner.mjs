import { randomUUID } from 'node:crypto';
import { chmod, link, open, rm } from 'node:fs/promises';
import { basename, dirname, join, resolve } from 'node:path';
import { CliError, HELP, parseArgs, sanitizeEndpoint } from './csd-config.mjs';
import {
  buildPreDocumentBootstrap,
  buildScenario,
  getScenario,
  listScenarios,
  REVIEWED_DESTINATION_HOSTS,
  renderManualScript,
  SCENARIO_NAMES,
} from './csd-scenarios.mjs';

export { CliError, parseArgs };

const loopback = (host) => ['localhost', '127.0.0.1', '[::1]', '::1'].includes(host.toLowerCase());

export class CdpClient {
  constructor(socket, timeoutMs) {
    this.socket = socket;
    this.timeoutMs = timeoutMs;
    this.nextId = 1;
    this.pending = new Map();
    this.listeners = new Set();
    this.closed = false;
    socket.addEventListener('message', (event) => this.receive(event.data));
    socket.addEventListener('close', () =>
      this.fail(new CliError('Chrome DevTools connection closed', 3, 'CDP_CLOSED')),
    );
  }
  static async connect(url, timeoutMs, WebSocketImpl, signal) {
    const socket = new WebSocketImpl(url);
    await new Promise((resolveOpen, reject) => {
      const timer = setTimeout(
        () => reject(new CliError('Chrome DevTools connection timed out', 3, 'CDP_TIMEOUT')),
        timeoutMs,
      );
      const finish = (callback, value) => {
        clearTimeout(timer);
        signal?.removeEventListener('abort', abort);
        callback(value);
      };
      const abort = () => finish(reject, new CliError('Chrome DevTools connection aborted', 3, 'ABORTED'));
      socket.addEventListener('open', () => finish(resolveOpen), { once: true });
      socket.addEventListener(
        'error',
        () => finish(reject, new CliError('Chrome DevTools connection failed', 3, 'CDP_CONNECT_FAILED')),
        { once: true },
      );
      signal?.addEventListener('abort', abort, { once: true });
    });
    return new CdpClient(socket, timeoutMs);
  }
  receive(data) {
    let message;
    try {
      message = JSON.parse(typeof data === 'string' ? data : data.toString());
    } catch {
      return;
    }
    if (message.id && this.pending.has(message.id)) {
      const item = this.pending.get(message.id);
      this.pending.delete(message.id);
      clearTimeout(item.timer);
      item.signal?.removeEventListener('abort', item.abort);
      if (message.error)
        item.reject(new CliError(`CDP ${item.method} failed: ${message.error.message}`, 3, 'CDP_ERROR'));
      else item.resolve(message.result || {});
      return;
    }
    if (message.method) for (const listener of this.listeners) listener(message);
  }
  onEvent(listener) {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }
  send(method, params = {}, sessionId, { signal } = {}) {
    if (this.closed) return Promise.reject(new CliError('Chrome DevTools connection is closed', 3, 'CDP_CLOSED'));
    const id = this.nextId++;
    return new Promise((resolveSend, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new CliError(`CDP ${method} timed out`, 3, 'CDP_TIMEOUT'));
      }, this.timeoutMs);
      const abort = () => {
        clearTimeout(timer);
        this.pending.delete(id);
        reject(new CliError(`CDP ${method} aborted`, 3, 'ABORTED'));
      };
      signal?.addEventListener('abort', abort, { once: true });
      this.pending.set(id, { resolve: resolveSend, reject, timer, method, signal, abort });
      this.socket.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }));
    });
  }
  fail(error) {
    this.closed = true;
    for (const item of this.pending.values()) {
      clearTimeout(item.timer);
      item.reject(error);
    }
    this.pending.clear();
  }
  close() {
    if (!this.closed) this.socket.close();
    this.closed = true;
    this.listeners.clear();
  }
}

function sanitizeUrl(value) {
  try {
    const url = new URL(value);
    return `${url.origin}${url.pathname}`;
  } catch {
    return '[invalid-url]';
  }
}
function documentResponseTracker(expectedOrigin, probe) {
  if (!probe) return { event() {}, value: () => null };
  if (typeof probe.path !== 'string' || !probe.path.startsWith('/') || probe.path.includes('#'))
    throw new CliError(
      'document response probe requires an exact path and optional query',
      2,
      'INVALID_DOCUMENT_PROBE',
    );
  let probeUrl;
  try {
    probeUrl = new URL(probe.path, expectedOrigin);
  } catch {
    throw new CliError(
      'document response probe requires an exact path and optional query',
      2,
      'INVALID_DOCUMENT_PROBE',
    );
  }
  if (probeUrl.origin !== expectedOrigin || `${probeUrl.pathname}${probeUrl.search}` !== probe.path)
    throw new CliError(
      'document response probe requires an exact path and optional query',
      2,
      'INVALID_DOCUMENT_PROBE',
    );
  if (!Array.isArray(probe.headers) || probe.headers.length === 0)
    throw new CliError('document response probe requires allowlisted headers', 2, 'INVALID_DOCUMENT_PROBE');
  const headers = probe.headers.map((header) => {
    const name = String(header?.name || '').toLowerCase();
    if (!/^[a-z0-9!#$%&'*+.^_`|~-]+$/.test(name) || typeof header.expectedValue !== 'string')
      throw new CliError('document response probe header is invalid', 2, 'INVALID_DOCUMENT_PROBE');
    return { name, expectedValue: header.expectedValue };
  });
  let observed = null;
  return {
    event(method, params = {}) {
      if (method !== 'Network.responseReceived' || params.type !== 'Document') return;
      let url;
      try {
        url = new URL(params.response?.url);
      } catch {
        return;
      }
      if (url.origin !== expectedOrigin || `${url.pathname}${url.search}` !== probe.path) return;
      const received = new Map(
        Object.entries(params.response?.headers || {}).map(([name, value]) => [name.toLowerCase(), String(value)]),
      );
      observed = {
        path: probe.path,
        status: Number(params.response?.status),
        observed: true,
        headers: headers.map(({ name, expectedValue }) => ({
          name,
          present: received.has(name),
          expected_match: received.get(name) === expectedValue,
        })),
      };
    },
    value: () =>
      observed || {
        path: probe.path,
        status: null,
        observed: false,
        headers: headers.map(({ name }) => ({ name, present: false, expected_match: false })),
      },
  };
}

function navigationGuard(expectedOrigin) {
  let error = null;
  const inspect = (value) => {
    if (error || !value || value === 'about:blank') return;
    try {
      if (new URL(value).origin !== expectedOrigin)
        error = new CliError('document navigation left the authorized target origin', 4, 'REDIRECT_HOST_DRIFT');
    } catch {
      error = new CliError('document navigation URL was invalid', 4, 'REDIRECT_HOST_DRIFT');
    }
  };
  return {
    event(method, params = {}) {
      if (method === 'Network.requestWillBeSent' && params.type === 'Document') inspect(params.request?.url);
      if (method === 'Page.frameNavigated' && !params.frame?.parentId) inspect(params.frame?.url);
    },
    assert() {
      if (error) throw error;
    },
  };
}

function networkTracker() {
  const records = new Map();
  const ordered = [];
  const current = (id) => records.get(id)?.at(-1);
  return {
    event(method, params = {}) {
      const id = String(params.requestId || '');
      if (!id) return;
      if (method === 'Network.requestWillBeSent') {
        let url;
        try {
          url = new URL(params.request?.url);
        } catch {
          return;
        }
        const previous = current(id);
        if (params.redirectResponse && previous) {
          previous.status = Number(params.redirectResponse.status);
          previous.outcome = 'redirected';
        }
        const reviewed = REVIEWED_DESTINATION_HOSTS.includes(url.hostname) || url.pathname.includes('/dip');
        const record = reviewed
          ? {
              request_id: id,
              redirect_hop: records.get(id)?.length || 0,
              destination_host: url.hostname,
              path: sanitizeUrl(url.href).slice(url.origin.length),
              method: params.request?.method || 'GET',
              resource_type: params.type || 'Other',
              outcome: 'pending',
            }
          : { reviewed: false, outcome: 'pending' };
        if (!records.has(id)) records.set(id, []);
        records.get(id).push(record);
        if (reviewed) ordered.push(record);
      } else if (current(id) && method === 'Network.responseReceived') {
        current(id).status = Number(params.response?.status);
      } else if (current(id) && method === 'Network.loadingFinished') current(id).outcome = 'finished';
      else if (current(id) && method === 'Network.loadingFailed') {
        current(id).outcome = 'failed';
        current(id).blocked_reason = String(params.blockedReason || params.errorText || 'request-failed').slice(0, 120);
      }
    },
    settle: () => {
      for (const record of ordered) if (record.outcome === 'pending') record.outcome = 'timed-out';
    },
    values: () => ordered.map((record) => ({ ...record })),
  };
}

const sleep = (ms, signal) =>
  new Promise((done, reject) => {
    if (!ms) return done();
    const timer = setTimeout(done, ms);
    signal?.addEventListener(
      'abort',
      () => {
        clearTimeout(timer);
        reject(new CliError('operation aborted', 3, 'ABORTED'));
      },
      { once: true },
    );
  });
async function evaluate(cdp, sessionId, expression, signal, awaitPromise = false) {
  const result = await cdp.send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise }, sessionId, {
    signal,
  });
  if (result.exceptionDetails) throw new CliError('browser evaluation failed', 4, 'EVALUATION_FAILED');
  return result.result?.value;
}
async function waitForDocument(cdp, sessionId, options, expectedOrigin, preconditions, signal) {
  const deadline = Date.now() + options.timeoutMs;
  while (Date.now() < deadline) {
    const state = await evaluate(
      cdp,
      sessionId,
      `(() => {
      const selectors = ${JSON.stringify(preconditions)};
      const sources = [];
      if (globalThis.__imp_apg__ && typeof globalThis.__imp_apg__ === 'object') sources.push('global');
      if (document.querySelector('script[src*="__imp_apg__"]')) sources.push('script');
      return { href: location.href, ready: document.readyState, top: top === self, instrumentation_sources: sources, selectors_ready: selectors.map((selector) => Boolean(document.querySelector(selector))) };
    })()`,
      signal,
    );
    if (state?.ready === 'complete') {
      const final = new URL(state.href);
      if (final.origin !== expectedOrigin)
        throw new CliError('redirected document origin drifted from authorized target', 4, 'REDIRECT_HOST_DRIFT');
      if (!state.top) throw new CliError('protected document is not top frame', 4, 'NOT_TOP_FRAME');
      if (!state.instrumentation_sources?.length)
        throw new CliError('protected document is missing __imp_apg__ instrumentation', 4, 'INSTRUMENTATION_MISSING');
      if (state.selectors_ready?.every(Boolean)) return state;
    }
    await sleep(50, signal);
  }
  throw new CliError('protected document route selectors did not become ready before timeout', 4, 'SELECTOR_TIMEOUT');
}

function expectedAttempts(operations) {
  return operations.flatMap((operation, operationIndex) =>
    Array.from({ length: operation.attempts || 1 }, (_, attemptIndex) => `${operationIndex}:${attemptIndex}`),
  );
}

function validateMarkers(name, operations, markers) {
  const start = markers.filter(({ type }) => type === 'run-start');
  const completed = markers.filter(({ type }) => type === 'completed');
  const terminal = markers.filter(({ type }) => type === 'terminal');
  if (start.length !== 1 || completed.length !== 1 || terminal.length !== 1)
    throw new CliError(`scenario ${name} is missing unique run lifecycle markers`, 4, 'IMMEDIATE_CONTRACT_FAILED');
  if (
    markers.indexOf(start[0]) > markers.indexOf(completed[0]) ||
    markers.indexOf(completed[0]) > markers.indexOf(terminal[0])
  )
    throw new CliError(`scenario ${name} lifecycle markers are out of order`, 4, 'IMMEDIATE_CONTRACT_FAILED');
  const expected = expectedAttempts(operations).sort();
  for (const type of ['operation-attempted', 'operation-settled']) {
    const actual = markers
      .filter((item) => item.type === type)
      .map((item) => `${item.operation_index}:${item.attempt_index}`)
      .sort();
    if (actual.length !== expected.length || actual.some((value, index) => value !== expected[index]))
      throw new CliError(`scenario ${name} has an invalid ${type} set`, 4, 'IMMEDIATE_CONTRACT_FAILED');
  }
  if (
    markers.filter(({ type }) => type === 'operation-settled').some(({ outcome }) => !outcome || outcome === 'pending')
  )
    throw new CliError(`scenario ${name} has pending or missing operation outcomes`, 4, 'IMMEDIATE_CONTRACT_FAILED');
}

function validateEvidencePredicates(name, predicates, markers) {
  const settled = markers.filter(({ type }) => type === 'operation-settled');
  const checks = {
    field_count_positive: (item) => item.field_count > 0,
    populated_count_positive: (item) => item.populated_count > 0,
    native_setter_count_positive: (item) => item.native_setter_count > 0,
    script_inserted: (item) => item.script_inserted === true,
    encoded_decoded_equal: (item) => item.encoded_decoded_equal === true,
    tag_manager_attribute: (item) => item.tag_manager_attribute === true,
    overlay_present: (item) => item.overlay_present === true,
    no_overlay_inputs: (item) => item.no_overlay_inputs === true,
    covers_target: (item) => item.geometry?.covers_target === true,
    masked_display_only: (item) => item.masked_display_only === true,
    banner_present: (item) => item.banner_present === true,
    key_count_positive: (item) => item.key_count > 0,
    flush_count_positive: (item) => item.flush_count > 0,
    listener_removed: (item) => item.listener_removed === true,
    timer_cleared: (item) => item.timer_cleared === true,
  };
  for (const predicate of predicates) {
    const items = settled.filter(({ operation_index: index }) => index === predicate.operationIndex);
    if (
      !items.length ||
      items.some(
        (item) =>
          !predicate.allowedOutcomes.includes(item.outcome) ||
          predicate.require.some((requirement) => !checks[requirement]?.(item)),
      )
    )
      throw new CliError(
        `scenario ${name} did not satisfy immediate evidence for operation ${predicate.operationIndex}`,
        4,
        'IMMEDIATE_CONTRACT_FAILED',
      );
  }
}

export async function runScenario(name, options, deps) {
  const definition = getScenario(name);
  const runId = deps.runId || randomUUID();
  const attemptId = randomUUID();
  const origin = new URL(options.target).origin;
  const built = buildScenario(name, { expectedOrigin: origin, runId, attemptId });
  const tracker = networkTracker();
  const responseTracker = documentResponseTracker(origin, options.documentResponseProbe);
  const navigation = navigationGuard(origin);
  const markers = [];
  let contextId;
  let targetId;
  let sessionId;
  let unsubscribe;
  let primaryError;
  let immediate;
  let document;
  const cleanup = {
    dom_cleanup_attempted: false,
    dom_cleanup_completed: false,
    target_closed: false,
    context_disposed: false,
    listeners_removed: false,
    errors: [],
  };
  try {
    ({ browserContextId: contextId } = await deps.cdp.send('Target.createBrowserContext', {}, undefined, {
      signal: deps.signal,
    }));
    ({ targetId } = await deps.cdp.send(
      'Target.createTarget',
      { url: 'about:blank', browserContextId: contextId },
      undefined,
      { signal: deps.signal },
    ));
    ({ sessionId } = await deps.cdp.send('Target.attachToTarget', { targetId, flatten: true }, undefined, {
      signal: deps.signal,
    }));
    unsubscribe = deps.cdp.onEvent?.((event) => {
      if (event.sessionId !== sessionId) return;
      navigation.event(event.method, event.params);
      if (event.method?.startsWith('Network.')) {
        tracker.event(event.method, event.params);
        responseTracker.event(event.method, event.params);
      }
      if (event.method === 'Runtime.bindingCalled' && event.params?.name === '__xcshCsdEvent') {
        try {
          const item = JSON.parse(event.params.payload);
          if (item.run_id === runId && item.attempt_id === attemptId && item.scenario === name)
            markers.push({
              type: item.type,
              scenario: item.scenario,
              attempt_id: item.attempt_id,
              operation_index: item.operation_index,
              attempt_index: item.attempt_index,
              kind: item.kind,
              outcome: item.outcome,
              destination_host: item.destination_host,
              duration_ms: item.duration_ms,
              status: item.status,
              field_count: item.field_count,
              populated_count: item.populated_count,
              native_setter_count: item.native_setter_count,
              key_count: item.key_count,
              flush_count: item.flush_count,
              script_inserted: item.script_inserted,
              encoded_decoded_equal: item.encoded_decoded_equal,
              tag_manager_attribute: item.tag_manager_attribute,
              overlay_present: item.overlay_present,
              masked_display_only: item.masked_display_only,
              no_overlay_inputs: item.no_overlay_inputs,
              geometry: item.geometry,
              listener_attached: item.listener_attached,
              listener_removed: item.listener_removed,
              timer_cleared: item.timer_cleared,
              overlay_removed: item.overlay_removed,
              banner_present: item.banner_present,
              primitive_names: item.primitive_names,
              field_values_discarded: item.field_values_discarded,
              key_values_discarded: item.key_values_discarded,
            });
        } catch {}
      }
    });
    for (const method of ['Page.enable', 'Runtime.enable', 'Network.enable', 'Log.enable'])
      await deps.cdp.send(method, {}, sessionId, { signal: deps.signal });
    await deps.cdp.send('Runtime.addBinding', { name: '__xcshCsdEvent' }, sessionId, { signal: deps.signal });
    await deps.cdp.send(
      'Page.addScriptToEvaluateOnNewDocument',
      { source: buildPreDocumentBootstrap({ expectedOrigin: origin, runId }) },
      sessionId,
      { signal: deps.signal },
    );
    const route = definition.route;
    const target = new URL(options.target);
    target.pathname = route.startsWith('/#/') ? '/' : route;
    target.hash = route.startsWith('/#/') ? route.slice(2) : '';
    const navigationResult = await deps.cdp.send('Page.navigate', { url: target.href }, sessionId, {
      signal: deps.signal,
    });
    if (navigationResult.errorText)
      throw new CliError(`navigation failed: ${navigationResult.errorText}`, 4, 'NAVIGATION_FAILED');
    document = await waitForDocument(deps.cdp, sessionId, options, origin, definition.preconditions, deps.signal);
    navigation.assert();
    immediate = await evaluate(deps.cdp, sessionId, built.script, deps.signal, true);
    if (
      !immediate?.attempted ||
      !immediate?.completed ||
      immediate.operation_count !== built.operations.length ||
      !immediate.cleanup_complete
    )
      throw new CliError(`scenario ${name} did not satisfy its immediate contract`, 4, 'IMMEDIATE_CONTRACT_FAILED');
    validateMarkers(name, built.operations, markers);
    validateEvidencePredicates(name, built.immediateEvidencePredicates, markers);
    const cleanupMarker = markers.find(({ type }) => type === 'cleanup');
    if (
      cleanupMarker?.overlay_removed !== true ||
      cleanupMarker.listener_removed !== true ||
      cleanupMarker.timer_cleared !== true
    )
      throw new CliError(`scenario ${name} cleanup evidence is incomplete`, 4, 'IMMEDIATE_CONTRACT_FAILED');
    await sleep(options.settleMs, deps.signal);
    tracker.settle();
    navigation.assert();
  } catch (error) {
    primaryError =
      error instanceof CliError ? error : new CliError(error.message || String(error), 4, 'SCENARIO_FAILED');
  } finally {
    if (sessionId) {
      cleanup.dom_cleanup_attempted = true;
      try {
        const result = await evaluate(
          deps.cdp,
          sessionId,
          `globalThis.__xcshCsdRuntime?.cleanup?.('runner-cleanup')`,
          undefined,
          true,
        );
        cleanup.dom_cleanup_completed =
          result?.completed === true &&
          result?.overlay_removed === true &&
          result?.listener_removed === true &&
          result?.timer_cleared === true &&
          (!Array.isArray(result.errors) || result.errors.length === 0);
        if (Array.isArray(result?.errors))
          cleanup.errors.push(...result.errors.map((error) => String(error).slice(0, 120)));
        if (!cleanup.dom_cleanup_completed && cleanup.errors.length === 0) cleanup.errors.push('dom-cleanup');
      } catch (error) {
        cleanup.errors.push(error.code || 'cleanup-evaluation');
      }
    }
    if (targetId)
      try {
        const result = await deps.cdp.send('Target.closeTarget', { targetId });
        if (result.success === true) cleanup.target_closed = true;
        else cleanup.errors.push('target-close');
      } catch (error) {
        cleanup.errors.push(error.code || 'target-close');
      }
    if (contextId)
      try {
        await deps.cdp.send('Target.disposeBrowserContext', { browserContextId: contextId });
        cleanup.context_disposed = true;
      } catch (error) {
        cleanup.errors.push(error.code || 'context-dispose');
      }
    if (unsubscribe)
      try {
        unsubscribe();
        cleanup.listeners_removed = true;
      } catch {
        cleanup.errors.push('listener-removal');
      }
  }
  tracker.settle();
  const network = tracker.values();
  const cleanupError = cleanup.errors.length
    ? { code: 'CLEANUP_FAILED', message: `scenario cleanup failed: ${cleanup.errors.join(', ')}` }
    : null;
  const error = primaryError ? { code: primaryError.code, message: primaryError.message } : cleanupError;
  const success = !error;
  const cleanupMarker = markers.find(({ type }) => type === 'cleanup');
  return {
    name,
    run_id: runId,
    attempt_id: attemptId,
    target: `${origin}${definition.route}`,
    status: success ? 'passed' : 'failed',
    error,
    operations_attempted: expectedAttempts(built.operations).length,
    field_count: immediate?.field_count ?? 0,
    populated_count: immediate?.populated_count ?? 0,
    key_count: immediate?.key_count ?? 0,
    flush_count: immediate?.flush_count ?? 0,
    field_values_discarded: true,
    key_values_discarded: true,
    immediate_evidence: { assertions: definition.immediateAssertions, assertions_met: !primaryError, markers },
    dom_cleanup: {
      overlay_removed: cleanupMarker?.overlay_removed === true,
      listener_removed: cleanupMarker?.listener_removed === true,
      timer_cleared: cleanupMarker?.timer_cleared === true,
    },
    console: [],
    network,
    protected_document: {
      origin,
      ready: Boolean(document),
      selectors: definition.preconditions,
      ...(options.documentResponseProbe ? { response_probe: responseTracker.value() } : {}),
    },
    instrumentation: {
      imp_apg_present: Boolean(document),
      sources: document?.instrumentation_sources || [],
      dip_observed: network.some((item) => item.path.includes('/dip')),
    },
    eventual_csd_evidence: null,
    expected_csd_evidence: definition.expectedEvidence,
    cleanup,
    success,
  };
}

async function atomicReceipt(path, value) {
  const destination = resolve(path);
  const temporary = join(dirname(destination), `.${basename(destination)}.${process.pid}.${randomUUID()}.tmp`);
  let handle;
  try {
    handle = await open(temporary, 'wx', 0o600);
    await handle.writeFile(`${JSON.stringify(value, null, 2)}\n`);
    await handle.sync();
    await handle.close();
    handle = null;
    await chmod(temporary, 0o600);
    await link(temporary, destination);
    await rm(temporary);
  } catch (error) {
    if (handle) await handle.close().catch(() => {});
    await rm(temporary, { force: true }).catch(() => {});
    if (error.code === 'EEXIST') throw new CliError(`receipt already exists: ${destination}`, 5, 'RECEIPT_COLLISION');
    throw new CliError(`receipt write failed: ${error.message}`, 5, 'RECEIPT_WRITE_FAILED');
  }
}

async function discover(options, fetchImpl) {
  if (options.cdpEndpoint.startsWith('ws:')) return options.cdpEndpoint;
  const response = await fetchImpl(new URL('/json/version', options.cdpEndpoint), {
    signal: AbortSignal.timeout(options.timeoutMs),
  });
  if (!response.ok) throw new CliError(`Chrome discovery failed with HTTP ${response.status}`, 3, 'DISCOVERY_FAILED');
  const body = await response.json();
  const url = new URL(body.webSocketDebuggerUrl);
  if (url.protocol !== 'ws:' || !loopback(url.hostname))
    throw new CliError('Chrome returned an unsafe browser WebSocket URL', 3, 'DISCOVERY_UNSAFE');
  return url.href;
}

export async function main(argv = process.argv.slice(2), overrides = {}) {
  const stdout = overrides.stdout || process.stdout;
  const stderr = overrides.stderr || process.stderr;
  let cdp;
  let options;
  let receipt;
  const started = Date.now();
  const abort = new AbortController();
  const signals = ['SIGINT', 'SIGTERM'];
  const handlers = signals.map((name) => {
    const fn = () => abort.abort();
    process.once(name, fn);
    return [name, fn];
  });
  try {
    options = parseArgs(argv);
    if (options.help) {
      stdout.write(HELP);
      return 0;
    }
    if (options.list) {
      stdout.write(
        `${JSON.stringify(
          listScenarios().map(({ operations, ...item }) => ({ ...item, operation_count: operations.length })),
          null,
          2,
        )}\n`,
      );
      return 0;
    }
    const origin = new URL(options.target).origin;
    if (options.printScript) {
      stdout.write(`${renderManualScript(options.printScript, { expectedOrigin: origin })}\n`);
      return 0;
    }
    receipt = {
      schema_version: 1,
      run_id: randomUUID(),
      started_at: new Date(started).toISOString(),
      ended_at: null,
      duration_ms: null,
      tool: { name: 'csd-traffic', runtime: process.version },
      requested_scenarios: options.all ? SCENARIO_NAMES : options.scenarios,
      target: { origin, routes: [] },
      allowlist: { allowed: true, exact_hosts: options.allowHosts },
      cdp_endpoint: sanitizeEndpoint(options.cdpEndpoint),
      scenarios: [],
      success: false,
      caveats: ['Immediate browser evidence does not guarantee asynchronous CSD detection or classification.'],
      eventual_csd_evidence: null,
    };
    const fetchImpl = overrides.fetch || globalThis.fetch;
    const WebSocketImpl = overrides.WebSocket || globalThis.WebSocket;
    if (!fetchImpl || !WebSocketImpl)
      throw new CliError('Node.js 22 browser APIs are required', 3, 'RUNTIME_UNSUPPORTED');
    cdp =
      overrides.cdp ||
      (await CdpClient.connect(await discover(options, fetchImpl), options.timeoutMs, WebSocketImpl, abort.signal));
    for (const name of receipt.requested_scenarios)
      receipt.scenarios.push(await runScenario(name, options, { cdp, signal: abort.signal, runId: receipt.run_id }));
    receipt.target.routes = receipt.scenarios.map(({ target }) => target);
    receipt.success = receipt.scenarios.every(({ success }) => success);
    if (!receipt.success) {
      const failed = receipt.scenarios.find(({ success }) => !success);
      receipt.error = failed?.error || { code: 'CLEANUP_FAILED', message: 'scenario cleanup failed' };
      receipt.exit_code = 4;
    }
  } catch (error) {
    const known =
      error instanceof CliError ? error : new CliError(error.message || String(error), 1, 'UNEXPECTED_ERROR');
    if (!receipt)
      receipt = {
        schema_version: 1,
        run_id: randomUUID(),
        started_at: new Date(started).toISOString(),
        scenarios: [],
        success: false,
        eventual_csd_evidence: null,
      };
    receipt.error = { code: known.code, message: known.message };
    receipt.exit_code = known.exitCode;
  } finally {
    if (cdp && !overrides.cdp) cdp.close();
    for (const [name, handler] of handlers) process.removeListener(name, handler);
  }
  receipt.ended_at = new Date().toISOString();
  receipt.duration_ms = Date.now() - started;
  let exitCode = receipt.success ? 0 : receipt.exit_code || 4;
  if (options?.receipt && options.receipt !== '-')
    try {
      await atomicReceipt(options.receipt, receipt);
    } catch (error) {
      receipt.success = false;
      const finalization = { code: error.code || 'RECEIPT_WRITE_FAILED', message: error.message };
      if (receipt.error) receipt.error.finalization = finalization;
      else receipt.error = finalization;
      exitCode = receipt.exit_code || error.exitCode || 5;
    }
  const serialized = `${JSON.stringify(receipt, null, 2)}\n`;
  if (options?.receipt === '-' || receipt.success) stdout.write(serialized);
  else stderr.write(`${JSON.stringify(receipt.error || { code: 'RUN_FAILED', message: 'run failed' })}\n`);
  return exitCode;
}
