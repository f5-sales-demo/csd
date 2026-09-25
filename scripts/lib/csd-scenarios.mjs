import { randomUUID } from 'node:crypto';

const DESTINATIONS = Object.freeze({
  httpbinPost: 'https://www.httpbin.org/post',
  httpbinImage: 'https://www.httpbin.org/image/png',
  jsonPosts: 'https://jsonplaceholder.typicode.com/posts',
  lodash: 'https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js',
  chart: 'https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js',
  moment: 'https://esm.sh/moment@2.30.1',
  underscore: 'https://unpkg.com/underscore@1.13.7/underscore-min.js',
  dayjs: 'https://ga.jspm.io/npm:dayjs@1.11.13/dayjs.min.js',
});

export const REVIEWED_DESTINATION_HOSTS = Object.freeze([
  'www.httpbin.org',
  'jsonplaceholder.typicode.com',
  'cdn.jsdelivr.net',
  'esm.sh',
  'unpkg.com',
  'ga.jspm.io',
]);

const CDN_CANDIDATES = Object.freeze([
  DESTINATIONS.lodash,
  DESTINATIONS.moment,
  DESTINATIONS.underscore,
  DESTINATIONS.dayjs,
]);
const LOGIN_SELECTORS = Object.freeze([
  'input[type="email"], input[name="email"], #email, #emailControl',
  'input[type="password"], input[name="password"], #password, #passwordControl',
]);
const REGISTER_SELECTORS = Object.freeze([
  'input[type="email"], input[name="email"], #emailControl',
  'input[type="password"], #passwordControl',
  'input[name="repeatPassword"], #repeatPasswordControl',
  'select[name="securityQuestion"], mat-select[name="securityQuestion"], #securityQuestion',
  'input[name="securityAnswer"], #securityAnswerControl',
]);

const observeLogin = () => ({ kind: 'observe-form', selector: 'input', populate: 'login' });
const observeRegistration = () => ({
  kind: 'observe-form',
  selector: 'input, select, mat-select',
  populate: 'registration',
});
const injectCdn = () => CDN_CANDIDATES.map((url) => ({ kind: 'inject-script', url }));
const channels = () => [
  { kind: 'fetch', url: DESTINATIONS.httpbinPost },
  { kind: 'image-beacon', url: DESTINATIONS.httpbinImage },
  { kind: 'prefetch', url: DESTINATIONS.jsonPosts },
];
const claim = (candidate, boundary) =>
  Object.freeze({
    candidate,
    claim_boundary: boundary,
    asynchronous: true,
    field_values_discarded: true,
    key_values_discarded: true,
  });
const evidencePredicates = (operations) =>
  Object.freeze(
    operations.map((operation, operationIndex) =>
      Object.freeze({
        operationIndex,
        kind: operation.kind,
        allowedOutcomes: Object.freeze(
          {
            'observe-form': ['completed'],
            'inject-script': ['loaded', 'blocked-or-failed', 'timed-out'],
            fetch: ['opaque-or-complete', 'blocked-or-failed', 'timed-out'],
            'image-beacon': ['loaded', 'blocked-or-failed', 'timed-out'],
            prefetch: ['loaded', 'blocked-or-failed', 'timed-out'],
            overlay: ['inserted'],
            banner: ['inserted'],
            'key-count': ['duration-complete'],
            compose: [],
          }[operation.kind] || [],
        ),
        require: Object.freeze([
          ...(operation.kind === 'observe-form' && !operation.optionalFieldCount ? ['field_count_positive'] : []),
          ...(operation.populate ? ['populated_count_positive', 'native_setter_count_positive'] : []),
          ...(operation.kind === 'inject-script' ? ['script_inserted'] : []),
          ...(operation.encoded ? ['encoded_decoded_equal'] : []),
          ...(operation.tagManager ? ['tag_manager_attribute'] : []),
          ...(operation.kind === 'overlay' ? ['overlay_present', 'no_overlay_inputs', 'covers_target'] : []),
          ...(operation.variant === 'payment' ? ['masked_display_only'] : []),
          ...(operation.kind === 'banner' ? ['banner_present'] : []),
          ...(operation.kind === 'key-count'
            ? ['key_count_positive', 'flush_count_positive', 'listener_removed', 'timer_cleared']
            : []),
        ]),
      }),
    ),
  );

const define = ({
  name,
  displayName,
  category,
  route,
  preconditions,
  syntheticInputPlan,
  operations,
  assertions,
  candidate,
  boundary,
}) => {
  const frozenOperations = Object.freeze(operations.map((operation) => Object.freeze({ ...operation })));
  return Object.freeze({
    name,
    displayName,
    category,
    route,
    preconditions: Object.freeze(preconditions),
    syntheticInputPlan,
    operations: frozenOperations,
    immediateAssertions: Object.freeze(assertions),
    immediateEvidencePredicates: evidencePredicates(frozenOperations),
    expectedEvidence: claim(candidate, boundary),
    cleanup: Object.freeze({ runScoped: true, always: true }),
  });
};

const REGISTRY = {
  'login-credential-skimmer': define({
    name: 'login-credential-skimmer',
    displayName: 'Login credential skimmer',
    category: 'form-access',
    route: '/#/login',
    preconditions: LOGIN_SELECTORS,
    syntheticInputPlan: 'Populate route controls through native value setters; report counts and populated state only.',
    operations: [observeLogin(), { kind: 'fetch', url: DESTINATIONS.httpbinPost }],
    assertions: [
      'login-fields-found',
      'field-and-populated-counts',
      'native-setters-used',
      'field-values-discarded',
      'fetch-terminal-state',
      'completion-marker',
    ],
    candidate: 'Matching field/script observations and observed destination, if present.',
    boundary:
      'Field and network activity is immediate browser evidence; CSD classification and timing are not guaranteed.',
  }),
  'registration-harvester': define({
    name: 'registration-harvester',
    displayName: 'Registration harvester',
    category: 'form-access',
    route: '/#/register',
    preconditions: REGISTER_SELECTORS,
    syntheticInputPlan: 'Populate documented synthetic placeholders through native setters; report counts only.',
    operations: [observeRegistration(), { kind: 'fetch', url: DESTINATIONS.jsonPosts }],
    assertions: [
      'registration-controls-found',
      'field-and-populated-counts',
      'native-setters-used',
      'field-values-discarded',
      'fetch-terminal-state',
      'completion-marker',
    ],
    candidate: 'Matching form-field/script telemetry and observed destination, if present.',
    boundary: 'No claim is made that every registration field is classified or visible in a bounded time.',
  }),
  'payment-overlay-card-skimmer': define({
    name: 'payment-overlay-card-skimmer',
    displayName: 'Payment overlay card skimmer',
    category: 'dom-overlay',
    route: '/#/login',
    preconditions: LOGIN_SELECTORS,
    syntheticInputPlan: 'Render masked display-only payment text; no payment input control or card value exists.',
    operations: [
      { kind: 'observe-form', selector: 'input' },
      { kind: 'overlay', variant: 'payment' },
      { kind: 'fetch', url: DESTINATIONS.httpbinPost },
    ],
    assertions: [
      'original-field-count',
      'overlay-present',
      'masked-display-only',
      'fetch-terminal-state',
      'overlay-removed',
    ],
    candidate: 'Original-field/script observations and external destination, if observed.',
    boundary:
      'Overlay rendering is browser evidence, not proof CSD detects the injected form; no card data is entered or retained.',
  }),
  'obfuscated-loader': define({
    name: 'obfuscated-loader',
    displayName: 'Obfuscated loader',
    category: 'script-injection',
    route: '/',
    preconditions: ['body'],
    syntheticInputPlan: 'Base64 round-trip the fixed lodash candidate URL.',
    operations: [{ kind: 'inject-script', url: DESTINATIONS.lodash, encoded: true }],
    assertions: ['encoded-decoded-url-equal', 'script-element-inserted', 'script-terminal-state', 'script-removed'],
    candidate: 'Matching script/domain record, if observed.',
    boundary:
      'Obfuscation and attempted injection are proven; detection and classification are asynchronous and not guaranteed.',
  }),
  'multi-cdn-injection': define({
    name: 'multi-cdn-injection',
    displayName: 'Multi-CDN injection',
    category: 'script-injection',
    route: '/',
    preconditions: ['body'],
    syntheticInputPlan: 'Inject four fixed benign CDN candidates.',
    operations: injectCdn(),
    assertions: ['four-script-insertions', 'individual-terminal-or-timeout-outcomes', 'scripts-removed'],
    candidate: 'Only the subset of script/domain records observed by the platform.',
    boundary: 'No claim is made that all four candidates loaded or were detected; every failure remains explicit.',
  }),
  'tag-manager-hijack': define({
    name: 'tag-manager-hijack',
    displayName: 'Tag manager hijack simulation',
    category: 'script-injection',
    route: '/',
    preconditions: ['body'],
    syntheticInputPlan: 'Attach run-scoped data-tag-manager metadata to the fixed Chart.js candidate.',
    operations: [
      { kind: 'inject-script', url: DESTINATIONS.chart, tagManager: 'reviewed-tag-manager-simulation' },
      { kind: 'observe-form', selector: 'input', optionalFieldCount: true },
    ],
    assertions: [
      'data-tag-manager-attribute',
      'script-element-inserted',
      'script-terminal-state',
      'optional-field-count',
      'script-removed',
    ],
    candidate: 'Matching Chart.js/domain and form observations, if present.',
    boundary: 'Tag-manager semantics are local metadata; no compromised-tag-manager platform attribution is claimed.',
  }),
  'multi-channel-exfiltration': define({
    name: 'multi-channel-exfiltration',
    displayName: 'Multi-channel exfiltration',
    category: 'network',
    route: '/#/login',
    preconditions: LOGIN_SELECTORS,
    syntheticInputPlan: 'Count and discard fields; send count-only signals through three benign channels.',
    operations: [observeLogin(), ...channels()],
    assertions: [
      'field-counts',
      'field-values-discarded',
      'three-channel-attempts',
      'terminal-or-timeout-outcomes',
      'channel-artifacts-removed',
    ],
    candidate: 'Field/script evidence and destination telemetry actually observed.',
    boundary:
      'Browser attempts are not platform detection proof; Network views may track source domains rather than destinations.',
  }),
  'high-volume-domain-exfiltration': define({
    name: 'high-volume-domain-exfiltration',
    displayName: 'High-volume domain exfiltration',
    category: 'network',
    route: '/#/login',
    preconditions: LOGIN_SELECTORS,
    syntheticInputPlan: 'Count and discard fields; make exactly five script and two POST attempts.',
    operations: [
      observeLogin(),
      ...injectCdn(),
      { kind: 'inject-script', url: DESTINATIONS.chart },
      { kind: 'fetch', url: DESTINATIONS.httpbinPost },
      { kind: 'fetch', url: DESTINATIONS.jsonPosts },
    ],
    assertions: [
      'field-counts',
      'field-values-discarded',
      'five-script-attempts',
      'two-post-attempts',
      'seven-network-outcomes',
      'artifacts-removed',
    ],
    candidate: 'Observed subset of scripts, domains, and form fields.',
    boundary: 'High volume means seven synthetic attempts, not volumetric load or guaranteed detections.',
  }),
  'form-overlay': define({
    name: 'form-overlay',
    displayName: 'Form overlay',
    category: 'dom-overlay',
    route: '/#/login',
    preconditions: LOGIN_SELECTORS,
    syntheticInputPlan: 'Cover the located login form with a run-scoped non-input overlay.',
    operations: [
      { kind: 'observe-form', selector: 'input' },
      { kind: 'overlay', variant: 'form' },
    ],
    assertions: [
      'original-field-count',
      'overlay-present',
      'overlay-covers-target',
      'no-overlay-inputs',
      'overlay-removed',
    ],
    candidate: 'Original-field/script access, if observed.',
    boundary:
      'DOM overlay and original-field reads are immediate evidence; dynamically created fields are not promised as a standalone signal.',
  }),
  'keylogger-simulation': define({
    name: 'keylogger-simulation',
    displayName: 'Keylogger simulation',
    category: 'event-observation',
    route: '/#/login',
    preconditions: LOGIN_SELECTORS,
    syntheticInputPlan: 'Generate bounded synthetic keyboard events; retain and POST aggregate counts only.',
    operations: [
      { kind: 'observe-form', selector: 'input' },
      { kind: 'key-count', durationMs: 600, flushMs: 200, syntheticEvents: 3, url: DESTINATIONS.httpbinPost },
    ],
    assertions: [
      'listener-attached',
      'aggregate-event-count',
      'periodic-count-only-posts',
      'key-values-discarded',
      'listener-removed',
      'timer-cleared',
    ],
    candidate: 'Form/script access and destination telemetry, if observed.',
    boundary:
      'Counts prove event handling only; no keystrokes are retained and no fixed-time classification is promised.',
  }),
};

REGISTRY['maximum-detection'] = define({
  name: 'maximum-detection',
  displayName: 'Maximum detection',
  category: 'composition',
  route: '/#/login',
  preconditions: LOGIN_SELECTORS,
  syntheticInputPlan:
    'Compose canonical field-observation, multi-CDN, three-channel request, and DOM-banner primitives once.',
  operations: [{ kind: 'compose', primitives: ['field-observation', 'multi-cdn', 'multi-channel', 'dom-banner'] }],
  assertions: [
    'canonical-primitives-listed',
    'no-duplicate-operations',
    'per-candidate-outcomes',
    'banner-removed',
    'single-run-id',
  ],
  candidate: 'Observed subset across scripts, domains, fields, and dashboard telemetry.',
  boundary:
    'This maximizes attempted signal coverage; it does not guarantee loads, telemetry population, timing, or classification.',
});

export const SCENARIOS = Object.freeze(REGISTRY);
export const SCENARIO_NAMES = Object.freeze(Object.keys(SCENARIOS));
export const listScenarios = () => SCENARIO_NAMES.map((name) => SCENARIOS[name]);
export function getScenario(name) {
  const result = SCENARIOS[name];
  if (!result) throw new RangeError(`Unknown CSD scenario: ${name}`);
  return result;
}
const clone = (value) => JSON.parse(JSON.stringify(value));

function expandOperations(definition) {
  if (definition.name !== 'maximum-detection') return clone(definition.operations);
  return [observeLogin(), ...injectCdn(), ...channels(), { kind: 'banner' }];
}
function exactOrigin(value) {
  const url = new URL(value);
  if (url.protocol !== 'https:' || url.origin !== value)
    throw new TypeError('expectedOrigin must be an exact HTTPS origin');
  return url.origin;
}
function validBinding(value) {
  if (!/^__[A-Za-z][A-Za-z0-9_]{0,63}$/.test(value)) throw new TypeError('bindingName is invalid');
  return value;
}

function runtimeSource(plan) {
  return `(${async function execute(plan) {
    globalThis.__xcshCsdRuntime?.cleanup?.('replaced');
    const cleanups = [];
    const events = [];
    let cleaned = false;
    const cleanupErrors = [];
    let fieldCount = 0;
    let populatedCount = 0;
    let keyCount = 0;
    let flushCount = 0;
    const report = (type, detail = {}) => {
      const event = Object.assign(
        {
          run_id: plan.runId,
          scenario: plan.name,
          attempt_id: plan.attemptId,
          type,
          field_values_discarded: true,
          key_values_discarded: true,
        },
        detail,
      );
      events.push(event);
      const sink = globalThis[plan.bindingName];
      if (typeof sink === 'function') sink(JSON.stringify(event));
    };
    const release = () => {
      if (cleaned) return cleanupErrors;
      cleaned = true;
      while (cleanups.length) {
        try {
          cleanups.pop()();
        } catch (error) {
          cleanupErrors.push(error?.name || 'cleanup-error');
        }
      }
      try {
        document.querySelectorAll(`[data-xcsh-csd-run="${CSS.escape(plan.runId)}"]`).forEach((node) => {
          node.remove();
        });
      } catch (error) {
        cleanupErrors.push(error?.name || 'cleanup-error');
      }
      return cleanupErrors;
    };
    const cleanup = (reason = 'cleaned') => {
      const errors = release();
      const result = {
        completed: errors.length === 0,
        overlay_removed: !document.querySelector(`[data-xcsh-csd-run="${CSS.escape(plan.runId)}"]`),
        listener_removed: errors.length === 0,
        timer_cleared: errors.length === 0,
        errors: [...errors],
      };
      report('cleanup', { status: reason, ...result });
      return result;
    };
    globalThis.__xcshCsdRuntime = { cleanup };
    if (top !== self || location.origin !== plan.expectedOrigin) {
      report('rejected', { reason: top !== self ? 'not-top-frame' : 'origin-mismatch' });
      cleanup('rejected');
      return { attempted: false, completed: false };
    }
    const attempted = (index, operation, attemptIndex = 0, detail = {}) =>
      report('operation-attempted', {
        operation_index: index,
        attempt_index: attemptIndex,
        kind: operation.kind,
        ...detail,
      });
    const settled = (index, operation, attemptIndex, outcome, detail = {}) =>
      report('operation-settled', {
        operation_index: index,
        attempt_index: attemptIndex,
        kind: operation.kind,
        outcome,
        ...detail,
      });
    const bounded = (start, timeout = 4000) =>
      new Promise((resolve) => {
        let done = false;
        const finish = (outcome, detail = {}) => {
          if (done) return;
          done = true;
          clearTimeout(timer);
          resolve({ outcome, detail });
        };
        const timer = setTimeout(() => finish('timed-out'), timeout);
        start(finish);
      });
    const countPayload = (kind, operationIndex, attemptIndex) =>
      JSON.stringify({
        kind,
        run_id: plan.runId,
        scenario: plan.name,
        operation_index: operationIndex,
        attempt_index: attemptIndex,
        field_count: fieldCount,
        populated_count: populatedCount,
        key_count: keyCount,
        flush_count: flushCount,
        field_values_discarded: true,
        key_values_discarded: true,
      });
    const setNative = (element, value) => {
      const prototype = element instanceof HTMLSelectElement ? HTMLSelectElement.prototype : HTMLInputElement.prototype;
      const setter = Object.getOwnPropertyDescriptor(prototype, 'value')?.set;
      if (setter) {
        setter.call(element, value);
        element.dispatchEvent(new Event('input', { bubbles: true }));
        element.dispatchEvent(new Event('change', { bubbles: true }));
        return true;
      }
      return false;
    };
    const handlers = {
      async 'observe-form'(operation, index) {
        const fields = [...document.querySelectorAll(operation.selector)];
        let nativeSetterCount = 0;
        if (operation.populate)
          fields.forEach((field) => {
            if (!('value' in field)) return;
            const marker = `synthetic-${plan.runId.slice(0, 8)}`;
            if (setNative(field, marker)) nativeSetterCount += 1;
          });
        fieldCount += fields.length;
        populatedCount += fields.filter((field) => Boolean(field.value)).length;
        attempted(index, operation, 0);
        settled(index, operation, 0, fields.length ? 'completed' : 'target-absent', {
          field_count: fields.length,
          populated_count: populatedCount,
          native_setter_count: nativeSetterCount,
          field_values_discarded: true,
        });
      },
      async 'inject-script'(operation, index) {
        const host = new URL(operation.url).hostname;
        attempted(index, operation, 0, { destination_host: host });
        let encodedDecodedEqual;
        const result = await bounded((finish) => {
          const node = document.createElement('script');
          const source = operation.encoded ? atob(btoa(operation.url)) : operation.url;
          encodedDecodedEqual = operation.encoded ? source === operation.url : undefined;
          node.src = source;
          node.dataset.xcshCsdRun = plan.runId;
          if (operation.tagManager) node.dataset.tagManager = `${operation.tagManager}-${plan.runId}`;
          node.addEventListener('load', () => finish('loaded'), { once: true });
          node.addEventListener('error', () => finish('blocked-or-failed'), { once: true });
          document.head.appendChild(node);
          cleanups.push(() => node.remove());
        });
        settled(index, operation, 0, result.outcome, {
          destination_host: host,
          script_inserted: true,
          ...(operation.encoded ? { encoded_decoded_equal: encodedDecodedEqual } : {}),
          ...(operation.tagManager ? { tag_manager_attribute: true } : {}),
        });
      },
      async fetch(operation, index) {
        const host = new URL(operation.url).hostname;
        attempted(index, operation, 0, { destination_host: host });
        const controller = new AbortController();
        cleanups.push(() => controller.abort());
        const result = await bounded((finish) =>
          fetch(operation.url, {
            method: 'POST',
            mode: 'no-cors',
            body: countPayload('fetch', index, 0),
            signal: controller.signal,
          })
            .then(() => finish('opaque-or-complete'))
            .catch(() => finish('blocked-or-failed')),
        );
        controller.abort();
        settled(index, operation, 0, result.outcome, { destination_host: host });
      },
      async 'image-beacon'(operation, index) {
        const host = new URL(operation.url).hostname;
        attempted(index, operation, 0, { destination_host: host });
        const result = await bounded((finish) => {
          const image = new Image();
          image.dataset.xcshCsdRun = plan.runId;
          image.addEventListener('load', () => finish('loaded'), { once: true });
          image.addEventListener('error', () => finish('blocked-or-failed'), { once: true });
          image.src = `${operation.url}?run_id=${encodeURIComponent(plan.runId)}&field_count=${fieldCount}`;
          document.body.appendChild(image);
          cleanups.push(() => {
            image.src = '';
            image.remove();
          });
        });
        settled(index, operation, 0, result.outcome, { destination_host: host });
      },
      async prefetch(operation, index) {
        const host = new URL(operation.url).hostname;
        attempted(index, operation, 0, { destination_host: host });
        const result = await bounded((finish) => {
          const node = document.createElement('link');
          node.rel = 'prefetch';
          node.href = `${operation.url}?run_id=${encodeURIComponent(plan.runId)}&field_count=${fieldCount}`;
          node.dataset.xcshCsdRun = plan.runId;
          node.addEventListener('load', () => finish('loaded'), { once: true });
          node.addEventListener('error', () => finish('blocked-or-failed'), { once: true });
          document.head.appendChild(node);
          cleanups.push(() => node.remove());
        });
        settled(index, operation, 0, result.outcome, { destination_host: host });
      },
      async overlay(operation, index) {
        const target = document.querySelector('form, [class*="login"], mat-card');
        attempted(index, operation);
        if (!target) {
          settled(index, operation, 0, 'target-absent', { overlay_present: false });
          return;
        }
        const targetRect = target.getBoundingClientRect();
        const node = document.createElement('div');
        node.dataset.xcshCsdRun = plan.runId;
        node.dataset.xcshCsdOverlay = operation.variant;
        node.setAttribute('role', 'presentation');
        node.textContent =
          operation.variant === 'payment'
            ? 'Payment card •••• •••• •••• •••• — display only'
            : 'Synthetic protected-form overlay';
        node.style.cssText = `position:fixed;left:${targetRect.left}px;top:${targetRect.top}px;width:${Math.max(targetRect.width, 1)}px;height:${Math.max(targetRect.height, 1)}px;z-index:2147483647;background:#fff;border:2px solid #c00;color:#111`;
        document.body.appendChild(node);
        cleanups.push(() => node.remove());
        const rect = node.getBoundingClientRect();
        settled(index, operation, 0, 'inserted', {
          overlay_present: node.isConnected,
          masked_display_only:
            operation.variant === 'payment' &&
            node.querySelectorAll('input,select,textarea').length === 0 &&
            node.textContent.includes('••••'),
          no_overlay_inputs: node.querySelectorAll('input,select,textarea').length === 0,
          geometry: {
            target_width: Math.round(targetRect.width),
            target_height: Math.round(targetRect.height),
            overlay_width: Math.round(rect.width),
            overlay_height: Math.round(rect.height),
            covers_target: rect.width >= targetRect.width && rect.height >= targetRect.height,
          },
        });
      },
      async banner(operation, index) {
        attempted(index, operation);
        const node = document.createElement('div');
        node.dataset.xcshCsdRun = plan.runId;
        node.textContent = 'Synthetic CSD signal';
        document.body.appendChild(node);
        cleanups.push(() => node.remove());
        settled(index, operation, 0, 'inserted', { banner_present: true });
      },
      async 'key-count'(operation, index) {
        let listenerAttached = true;
        let timerCleared = false;
        const listener = () => {
          keyCount += 1;
        };
        document.addEventListener('keydown', listener);
        attempted(index, operation, 0, { listener_attached: true });
        let interval;
        let timeout;
        const finish = new Promise((resolve) => {
          interval = setInterval(() => {
            flushCount += 1;
            const controller = new AbortController();
            cleanups.push(() => controller.abort());
            fetch(operation.url, {
              method: 'POST',
              mode: 'no-cors',
              body: countPayload('key-count', index, flushCount),
              signal: controller.signal,
            })
              .catch(() => {})
              .finally(() => controller.abort());
            report('key-count-flush', {
              operation_index: index,
              attempt_index: flushCount - 1,
              key_count: keyCount,
              flush_count: flushCount,
              destination_host: new URL(operation.url).hostname,
            });
          }, operation.flushMs);
          timeout = setTimeout(resolve, operation.durationMs);
        });
        cleanups.push(() => {
          document.removeEventListener('keydown', listener);
          listenerAttached = false;
          clearInterval(interval);
          clearTimeout(timeout);
          timerCleared = true;
        });
        for (let count = 0; count < operation.syntheticEvents; count += 1)
          document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Unidentified' }));
        await finish;
        document.removeEventListener('keydown', listener);
        listenerAttached = false;
        clearInterval(interval);
        clearTimeout(timeout);
        timerCleared = true;
        settled(index, operation, 0, 'duration-complete', {
          key_count: keyCount,
          flush_count: flushCount,
          listener_removed: !listenerAttached,
          timer_cleared: timerCleared,
          key_values_discarded: true,
        });
      },
    };
    report('run-start', { status: 'started', primitive_names: plan.primitiveNames });
    try {
      for (let index = 0; index < plan.operations.length; index += 1)
        await handlers[plan.operations[index].kind](plan.operations[index], index);
      report('completed', {
        field_count: fieldCount,
        populated_count: populatedCount,
        key_count: keyCount,
        flush_count: flushCount,
      });
      const cleanupResult = cleanup('completed');
      report('terminal', { status: cleanupResult.completed ? 'completed' : 'cleanup-failed' });
      return {
        attempted: true,
        completed: true,
        operation_count: plan.operations.length,
        field_count: fieldCount,
        populated_count: populatedCount,
        key_count: keyCount,
        flush_count: flushCount,
        cleanup_complete: cleanupResult.completed,
        events,
      };
    } catch (error) {
      report('failed', { reason: error?.name || 'runtime-error' });
      const cleanupResult = cleanup('failed');
      return {
        attempted: true,
        completed: false,
        operation_count: plan.operations.length,
        field_count: fieldCount,
        populated_count: populatedCount,
        key_count: keyCount,
        flush_count: flushCount,
        cleanup_complete: cleanupResult.completed,
        events,
      };
    }
  }})(${JSON.stringify(plan)});`;
}

export function buildScenario(
  name,
  { expectedOrigin, runId = randomUUID(), attemptId = randomUUID(), bindingName = '__xcshCsdEvent' } = {},
) {
  const definition = getScenario(name);
  const operations = Object.freeze(expandOperations(definition));
  const immediateEvidencePredicates = evidencePredicates(operations);
  const plan = Object.freeze({
    name,
    runId: String(runId),
    attemptId: String(attemptId),
    expectedOrigin: exactOrigin(expectedOrigin),
    bindingName: validBinding(bindingName),
    route: definition.route,
    preconditions: definition.preconditions,
    operations,
    primitiveNames: name === 'maximum-detection' ? definition.operations[0].primitives : [],
  });
  return Object.freeze({
    ...plan,
    expectedEvidence: definition.expectedEvidence,
    immediateAssertions: definition.immediateAssertions,
    immediateEvidencePredicates,
    cleanup: definition.cleanup,
    script: runtimeSource(clone(plan)),
  });
}
export function buildPreDocumentBootstrap({ expectedOrigin, runId = randomUUID(), bindingName = '__xcshCsdEvent' }) {
  const config = {
    expectedOrigin: exactOrigin(expectedOrigin),
    runId: String(runId),
    bindingName: validBinding(bindingName),
  };
  return `(() => { const config=${JSON.stringify(config)}; globalThis.__xcshCsdRuntime?.cleanup?.('replaced'); globalThis.__xcshCsdBootstrap=Object.freeze(config); })();`;
}
export function renderManualScript(name, options = {}) {
  const built = buildScenario(name, options);
  return `// XCSH CSD authorized demo; run ${built.runId}; expected origin ${built.expectedOrigin}\n${built.script}`;
}
