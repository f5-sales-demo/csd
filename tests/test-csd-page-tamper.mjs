import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdir, mkdtemp, readdir, readFile, stat, utimes, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import {
  classifyAlerts,
  correlateAlerts,
  correlateAlertViews,
  flattenAlertPayload,
} from '../scripts/lib/csd-page-tamper-alerts.mjs';
import {
  bootstrap,
  ControllerError,
  createDependencies,
  DEFAULT_TIMINGS,
  HEADER_IDS,
  HEADER_VALUES,
  runHeader,
  runSuite,
  runWorkerProbe,
  status,
  validateDeploymentIdentity,
} from '../scripts/lib/csd-page-tamper-controller.mjs';

const START = '2026-09-25T12:00:00.000Z';
const config = (root, overrides = {}) => ({
  target: 'https://client-side-defense.f5-sales-demo.com/csd-page-tamper/payment',
  awsAccount: '280469140135',
  awsProfile: 'Users-280469140135',
  awsRegion: 'us-east-1',
  namespace: 'client-side-defense',
  lbName: 'client-side-defense',
  workerInstance: 'i-0123456789abcdef0',
  terraformDir: join(root, 'terraform'),
  receiptDir: join(root, 'receipts'),
  f5ApiUrl: 'https://f5-sales-demo.console.ves.volterra.io',
  f5ApiToken: 'secret-not-for-receipts',
  probeTimeoutMs: 10,
  probeSettleMs: 0,
  timings: {
    ...DEFAULT_TIMINGS,
    reinforcementMs: 0,
    mixedMs: 1_000,
    recoveryMs: 0,
    pollMs: 0,
    reinforcementProfiles: 1,
    minimumPairs: 1,
    maximumCaseMs: 2_000,
    bootstrapControlMs: 0,
    quietMs: 0,
  },
  ...overrides,
});

async function workspace() {
  const root = await mkdtemp(join(tmpdir(), 'csd-page-tamper-test-'));
  await mkdir(join(root, 'terraform'), { recursive: true });
  await writeFile(
    join(root, 'terraform', 'versions.tf'),
    'bucket       = "terraform-tfstate-xc"\nkey          = "f5-sales-demo/client-side-defense.tfstate"\n',
  );
  return root;
}

const outputs = {
  aws_account_id: { value: '280469140135' },
  aws_region: { value: 'us-east-1' },
  application_url: { value: 'https://client-side-defense.f5-sales-demo.com' },
  xc_namespace: { value: 'client-side-defense' },
  xc_http_loadbalancer_name: { value: 'client-side-defense' },
  page_tamper_target_group_arn: {
    value: 'arn:aws:elasticloadbalancing:us-east-1:280469140135:targetgroup/page-tamper/1234',
  },
};

function executor({ driftCode = 0 } = {}) {
  return async (argv) => {
    if (argv[0] === 'aws' && argv[1] === 'sts')
      return { code: 0, stdout: JSON.stringify({ Account: '280469140135' }), stderr: '' };
    if (argv[0] === 'aws' && argv[1] === 'ec2')
      return {
        code: 0,
        stdout: JSON.stringify({
          Reservations: [{ Instances: [{ InstanceId: 'i-0123456789abcdef0', State: { Name: 'running' } }] }],
        }),
        stderr: '',
      };
    if (argv.includes('output')) return { code: 0, stdout: JSON.stringify(outputs), stderr: '' };
    if (argv.includes('plan')) return { code: driftCode, stdout: '', stderr: '' };
    throw new Error(`unexpected command: ${argv.join(' ')}`);
  };
}

function probe({ headerId } = {}) {
  return {
    success: true,
    document: {
      observed: true,
      status: 200,
      headers: HEADER_IDS.map((name) => ({
        name,
        present: name !== headerId,
        expected_match: name !== headerId,
        expected_value: HEADER_VALUES[name],
        observed_value: name === headerId ? null : HEADER_VALUES[name],
      })),
      fields_present: ['cardholder_name', 'card_number', 'expiry', 'cvv', 'billing_postal_code'],
      fields_empty: true,
    },
    instrumentation: { imp_apg_present: true, dip_post_observed: true },
  };
}

function alert(name = 'ClientSideDefenseHttpHeaderCompromised', overrides = {}) {
  return {
    labels: {
      alertname: name,
      namespace: 'client-side-defense',
      path: '/csd-page-tamper/payment',
      header: 'X-Content-Type-Options',
    },
    startsAt: START,
    status: 'firing',
    description: 'sanitized description',
    ...overrides,
  };
}

function deps(overrides = {}) {
  let now = Date.parse(START);
  return createDependencies({
    executor: executor(),
    probe,
    workerProbe: ({ headerId }) => probe({ headerId }),
    readiness: async () => ({
      endpoint_health: true,
      payment_health: true,
      application_health: true,
      lb_ready: true,
      certificate_valid: true,
    }),
    cleanup: async () => ({ worker_artifacts_removed: true, browser_artifacts_removed: true }),
    alertSource: async () => [[alert()]],
    sleep: async (ms) => {
      now += ms;
    },
    now: () => new Date(now).toISOString(),
    nowMs: () => now,
    randomUUID: () => '00000000-0000-4000-8000-000000000001',
    env: {},
    ...overrides,
  });
}

test('canonical header registry has exactly the reviewed 12 IDs and values', () => {
  assert.equal(HEADER_IDS.length, 12);
  assert.deepEqual(HEADER_IDS, [
    'cache-control',
    'clear-site-data',
    'content-security-policy',
    'cross-origin-embedder-policy',
    'cross-origin-opener-policy',
    'cross-origin-resource-policy',
    'permissions-policy',
    'referrer-policy',
    'strict-transport-security',
    'x-content-type-options',
    'x-frame-options',
    'x-permitted-cross-domain-policies',
  ]);
  assert.equal(HEADER_VALUES['cache-control'], 'no-store, max-age=0');
  assert.equal(HEADER_VALUES['clear-site-data'], '"cache"');
  assert.equal(HEADER_VALUES['x-content-type-options'], 'nosniff');
});

test('deployment identity accepts only the reviewed deployment', async () => {
  const root = await workspace();
  await assert.doesNotReject(validateDeploymentIdentity(config(root), deps()));
  for (const patch of [
    { namespace: 'other' },
    { awsRegion: 'westus' },
    { target: 'https://example.invalid/csd-page-tamper/payment' },
    { lbName: 'other' },
  ]) {
    await assert.rejects(
      validateDeploymentIdentity(config(root, patch), deps()),
      (error) => error instanceof ControllerError && error.code === 'IDENTITY_MISMATCH',
    );
  }
});

test('history JSON strings parse and exact current/history matches dedupe', () => {
  const expected = {
    namespace: 'client-side-defense',
    path: '/csd-page-tamper/payment',
    headerId: 'x-content-type-options',
    windowStart: '2026-09-25T11:59:00.000Z',
    windowEnd: '2026-09-25T12:01:00.000Z',
  };
  const raw = alert();
  assert.equal(flattenAlertPayload({ items: [JSON.stringify(raw)] }).length, 1);
  const matches = correlateAlerts([[raw], { items: [JSON.stringify(raw)] }], expected);
  assert.equal(matches.length, 1);
  assert.equal(matches[0].state, 'firing');
  const resolved = correlateAlerts(
    [[raw, { ...raw, endsAt: '2026-09-25T12:00:30.000Z', status: 'resolved' }]],
    expected,
  );
  assert.deepEqual(
    resolved.map(({ state }) => state),
    ['firing', 'resolved'],
  );
});
test('current firing alerts may predate bootstrap while stale resolved history remains excluded', () => {
  const expected = {
    namespace: 'client-side-defense',
    path: '/csd-page-tamper/payment',
    headerId: 'x-content-type-options',
    windowStart: START,
    windowEnd: '2026-09-25T12:01:00.000Z',
  };
  const old = alert(undefined, { startsAt: '2026-09-25T11:00:00.000Z' });
  const matches = correlateAlertViews(
    {
      current: [old],
      history: [{ ...old, status: 'resolved', endsAt: '2026-09-25T11:30:00.000Z' }],
    },
    expected,
  );
  assert.deepEqual(
    matches.map(({ state }) => state),
    ['firing'],
  );
});

test('correlation rejects wrong path, header, namespace, stale, future, and generic alerts', () => {
  const expected = {
    namespace: 'client-side-defense',
    path: '/csd-page-tamper/payment',
    headerId: 'x-content-type-options',
    windowStart: '2026-09-25T11:59:00.000Z',
    windowEnd: '2026-09-25T12:01:00.000Z',
  };
  const invalid = [
    alert('OtherAlert'),
    alert(undefined, { labels: { ...alert().labels, path: '/other' } }),
    alert(undefined, { labels: { ...alert().labels, header: 'x-frame-options' } }),
    alert(undefined, { labels: { ...alert().labels, namespace: 'other' } }),
    alert(undefined, { startsAt: '2026-09-25T11:58:59.999Z' }),
    alert(undefined, { startsAt: '2026-09-25T12:01:00.001Z' }),
  ];
  assert.equal(correlateAlerts([invalid], expected).length, 0);
  assert.equal(
    correlateAlerts([[alert(undefined, { labels: { ...alert().labels, header: 'X-CONTENT-TYPE-OPTIONS' } })]], expected)
      .length,
    1,
  );
});

test('classification produces mutually exclusive outcomes', () => {
  assert.equal(classifyAlerts([], false), 'INVALID_TEST');
  assert.equal(classifyAlerts([], true), 'NO_ALERT_WITHIN_WINDOW');
  assert.equal(classifyAlerts([{ alert_name: 'ClientSideDefenseHttpHeaderModified' }]), 'MODIFIED_ONLY');
  assert.equal(
    classifyAlerts([
      { alert_name: 'ClientSideDefenseHttpHeaderModified' },
      { alert_name: 'ClientSideDefenseHttpHeaderCompromised' },
    ]),
    'COMPROMISED',
  );
});

test('worker shell identity predicate accepts valid PID and rejects unsafe pairs', () => {
  const predicate = `case "$1:$2" in :*|*:|*[!0-9:]*|0:*|*:0) exit 1;; esac; if [ "$1" = "$3" ] || [ "$2" = "$4" ] || [ "$1" = "$4" ] || [ "$2" = "$3" ]; then exit 1; fi`;
  const run = (pair, launcher = '1:2') =>
    spawnSync('/bin/sh', ['-c', predicate, 'sh', ...pair.split(':'), ...launcher.split(':')], { encoding: 'utf8' });
  for (const pair of ['', ':2', '2:', '0:2', '2:0', 'a:2', '2:b', '2:3']) assert.notEqual(run(pair).status, 0, pair);
  assert.equal(run('77398:77398', '1:2').status, 0);
  assert.notEqual(run('77398:77398', '77398:2').status, 0);
});

test('runHeader completes phases, correlation, recovery, receipt, and lock cleanup', async () => {
  const root = await workspace();
  const result = await runHeader(config(root), deps(), 'x-content-type-options');
  assert.equal(result.outcome, 'COMPROMISED');
  assert.equal(result.phases.control_reinforcement.completed, 1);
  assert.equal(result.phases.mixed.completed_pairs, 1);
  assert.equal(result.recovery.success, true);
  const files = await readdir(join(root, 'receipts'));
  assert.equal(files.includes('active.lock'), false);
  const receiptName = files.find((name) => name.endsWith('.json'));
  const receiptPath = join(root, 'receipts', receiptName);
  assert.equal((await stat(receiptPath)).mode & 0o777, 0o600);
  const serialized = await readFile(receiptPath, 'utf8');
  assert.doesNotMatch(
    serialized,
    /secret-not-for-receipts|Authorization|cookie|browserContext|terraform-tfstate|280469140135|Users-280469140135/,
  );
  assert.equal(
    (await readdir(join(root, 'receipts'))).some((name) => name.endsWith('.tmp')),
    false,
  );
});

test('exact Compromised ends mixed phase before minimum pairs', async () => {
  const root = await workspace();
  const result = await runHeader(
    config(root, { timings: { ...config(root).timings, minimumPairs: 20 } }),
    deps(),
    'x-content-type-options',
  );
  assert.equal(result.outcome, 'COMPROMISED');
  assert.ok(result.phases.mixed.completed_pairs < 20);
});

test('overlap lock rejects a second run without replacing the lock', async () => {
  const root = await workspace();
  await mkdir(join(root, 'receipts'), { recursive: true });
  await writeFile(join(root, 'receipts', 'active.lock'), JSON.stringify({ run_id: 'existing', started_at: START }));
  await assert.rejects(runHeader(config(root), deps(), 'x-content-type-options'), (error) => error.code === 'OVERLAP');
  assert.match(await readFile(join(root, 'receipts', 'active.lock'), 'utf8'), /existing/);
});

test('deadline without required pairs is invalid and recovery still runs', async () => {
  const root = await workspace();
  let now = Date.parse(START);
  const injected = deps({
    alertSource: async () => [],
    now: () => new Date(now).toISOString(),
    nowMs: () => {
      now += 10_000;
      return now;
    },
  });
  const result = await runHeader(
    config(root, { timings: { ...config(root).timings, minimumPairs: 2, maximumCaseMs: 1 } }),
    injected,
    'x-content-type-options',
  );
  assert.equal(result.outcome, 'INVALID_TEST');
  assert.equal(result.recovery.success, true);
});

test('failed run retains recovery-required lock when recovery fails', async () => {
  const root = await workspace();
  let calls = 0;
  const result = await runHeader(
    config(root),
    deps({
      probe: ({ headerId }) => {
        calls += 1;
        return calls === 1 ? { success: false } : probe({ headerId });
      },
      cleanup: async () => ({ worker_artifacts_removed: false, browser_artifacts_removed: true }),
    }),
    'x-content-type-options',
  );
  assert.equal(result.outcome, 'INVALID_TEST');
  assert.equal(result.recovery.success, false);
  const lock = JSON.parse(await readFile(join(root, 'receipts', 'active.lock'), 'utf8'));
  assert.equal(lock.state, 'recovery-required');
});

test('status detects an interrupted run using the bounded case deadline', async () => {
  const root = await workspace();
  await mkdir(join(root, 'receipts'), { recursive: true });
  await writeFile(join(root, 'receipts', 'active.lock'), JSON.stringify({ run_id: 'interrupted', started_at: START }));
  await new Promise((resolve) => setTimeout(resolve, 5));
  const result = await status(config(root, { timings: { ...config(root).timings, maximumCaseMs: 1 } }));
  assert.equal(result.active, true);
  assert.equal(result.interrupted, true);
  assert.equal(result.cleanup_required, true);
});

test('concurrent stale recovery is claimed by exactly one command', async () => {
  const root = await workspace();
  await mkdir(join(root, 'receipts'), { recursive: true });
  await writeFile(
    join(root, 'receipts', 'active.lock'),
    JSON.stringify({ run_id: 'original-run', command: 'run', started_at: START, state: 'recovery-required' }),
  );
  let releaseRecovery;
  const recoveryPaused = new Promise((resolve) => {
    releaseRecovery = resolve;
  });
  let recoveryEntered;
  const entered = new Promise((resolve) => {
    recoveryEntered = resolve;
  });
  let readinessCalls = 0;
  const firstDeps = deps({
    readiness: async () => {
      readinessCalls += 1;
      if (readinessCalls === 1) {
        recoveryEntered();
        await recoveryPaused;
      }
      return {
        endpoint_health: true,
        payment_health: true,
        application_health: true,
        lb_ready: true,
        certificate_valid: true,
      };
    },
  });
  const first = runHeader(config(root), firstDeps, 'x-content-type-options');
  await entered;
  await assert.rejects(runHeader(config(root), deps(), 'x-content-type-options'), (error) => error.code === 'OVERLAP');
  releaseRecovery();
  const result = await first;
  assert.equal(result.recovery.success, true);
  const recoveryReceipts = (await readdir(join(root, 'receipts'))).filter((name) =>
    name.startsWith('recovery-original-run-'),
  );
  assert.equal(recoveryReceipts.length, 1);
  await assert.rejects(stat(join(root, 'receipts', 'recovery.claim')), /ENOENT/);
});

test('successful interrupted recovery retains active state when owned claim release fails', async () => {
  const root = await workspace();
  const receiptDir = join(root, 'receipts');
  const claimDir = join(receiptDir, 'recovery.claim');
  await mkdir(receiptDir, { recursive: true });
  await writeFile(
    join(receiptDir, 'active.lock'),
    JSON.stringify({ run_id: 'original-run', command: 'run', started_at: START, state: 'recovery-required' }),
  );
  const injected = deps({
    remove: async (path, options) => {
      if (path === claimDir) throw new Error('simulated claim release failure');
      const { rm } = await import('node:fs/promises');
      return rm(path, options);
    },
  });
  await assert.rejects(runHeader(config(root), injected, 'x-content-type-options'), /simulated claim release failure/);
  assert.equal((await status(config(root))).active, true);
  const owner = JSON.parse(await readFile(join(claimDir, 'owner.json'), 'utf8'));
  assert.equal(owner.run_id, 'original-run');
});

test('stale recovery claim takeover is exclusive under deterministic contention', async () => {
  const root = await workspace();
  const receiptDir = join(root, 'receipts');
  const claimDir = join(receiptDir, 'recovery.claim');
  await mkdir(claimDir, { recursive: true });
  await writeFile(
    join(claimDir, 'owner.json'),
    JSON.stringify({ claim_id: 'stale-owner', run_id: 'original-run', claimed_at: START }),
  );
  await utimes(claimDir, new Date(0), new Date(0));
  await writeFile(
    join(receiptDir, 'active.lock'),
    JSON.stringify({ run_id: 'original-run', command: 'run', started_at: START, state: 'recovery-required' }),
  );

  let releaseRecovery;
  const recoveryPaused = new Promise((resolve) => {
    releaseRecovery = resolve;
  });
  let recoveryEntered;
  const entered = new Promise((resolve) => {
    recoveryEntered = resolve;
  });
  let readinessCalls = 0;
  const first = runHeader(
    config(root, { timings: { ...config(root).timings, maximumCaseMs: 1 } }),
    deps({
      readiness: async () => {
        readinessCalls += 1;
        if (readinessCalls === 1) {
          recoveryEntered();
          await recoveryPaused;
        }
        return {
          endpoint_health: true,
          payment_health: true,
          application_health: true,
          lb_ready: true,
          certificate_valid: true,
        };
      },
    }),
    'x-content-type-options',
  );
  await entered;
  await assert.rejects(
    runHeader(
      config(root, { timings: { ...config(root).timings, maximumCaseMs: 1 } }),
      deps(),
      'x-content-type-options',
    ),
    (error) => error.code === 'OVERLAP',
  );
  releaseRecovery();
  const result = await first;
  assert.equal(result.recovery.success, true);
  assert.equal((await readdir(receiptDir)).filter((name) => name.startsWith('recovery-claim-stale-')).length, 1);
  await assert.rejects(stat(claimDir), /ENOENT/);
});

test('suite stops after recovered canary failure', async () => {
  const root = await workspace();
  const result = await runSuite(config(root), deps({ alertSource: async () => [] }));
  assert.equal(result.results.length, 1);
  assert.equal(result.results[0].header_id, 'x-content-type-options');
  assert.equal(result.results[0].outcome, 'NO_ALERT_WITHIN_WINDOW');
  assert.equal(result.results[0].recovery_success, true);
  assert.equal(result.success, false);
});

test('suite continues all headers after successful canary and tolerates measured non-canary outcomes', async () => {
  const root = await workspace();
  let runs = 0;
  const injected = deps({
    alertSource: async () => {
      runs += 1;
      return runs <= 1 ? [[alert()]] : [];
    },
  });
  const result = await runSuite(config(root), injected);
  assert.equal(result.results.length, HEADER_IDS.length);
  assert.equal(result.results[0].outcome, 'COMPROMISED');
  assert.equal(
    result.results.some(({ outcome }) => outcome === 'NO_ALERT_WITHIN_WINDOW'),
    true,
  );
  assert.equal(result.success, false);
});

test('bootstrap correlates object-shaped current and history API views without duplication', async () => {
  const root = await workspace();
  let now = Date.parse(START);
  const currentAlert = alert();
  const resolvedAlert = { ...currentAlert, status: 'resolved', endsAt: '2026-09-25T12:00:30.000Z' };
  const result = await bootstrap(
    config(root, { timings: { ...config(root).timings, bootstrapControlMs: 2, quietMs: 0, pollMs: 1 } }),
    deps({
      alertSource: null,
      fetch: async (url) => ({
        ok: true,
        json: async () =>
          url.endsWith('/history')
            ? { data: [{ items: [JSON.stringify(resolvedAlert)] }] }
            : { data: [{ items: [JSON.stringify(currentAlert)] }] },
      }),
      sleep: async (ms) => {
        now += ms;
      },
      now: () => new Date(now).toISOString(),
      nowMs: () => now,
    }),
  );
  assert.equal(result.success, true);
  assert.equal(result.alerts.length, 2);
  assert.deepEqual(
    result.alerts.map(({ state }) => state),
    ['firing', 'resolved'],
  );
});

test('production alert polling normalizes current and history without duplicate bootstrap alerts', async () => {
  const root = await workspace();
  let now = Date.parse(START);
  const urls = [];
  const currentAlert = alert();
  const result = await bootstrap(
    config(root, { timings: { ...config(root).timings, bootstrapControlMs: 2, quietMs: 0, pollMs: 1 } }),
    deps({
      alertSource: null,
      fetch: async (url) => {
        urls.push(url);
        return {
          ok: true,
          json: async () => (url.endsWith('/history') ? [] : [currentAlert]),
        };
      },
      sleep: async (ms) => {
        now += ms;
      },
      now: () => new Date(now).toISOString(),
      nowMs: () => now,
    }),
  );
  assert.equal(result.success, true);
  assert.equal(result.alerts.length, 1);
  assert.ok(urls.some((url) => url.endsWith('/alerts')));
  assert.ok(urls.some((url) => url.endsWith('/alerts/history')));
});

test('suite final cleanup failure persists evidence and blocks new runs', async () => {
  const root = await workspace();
  let cleanupCalls = 0;
  const result = await runSuite(
    config(root),
    deps({
      cleanup: async () => {
        cleanupCalls += 1;
        return { worker_artifacts_removed: cleanupCalls <= HEADER_IDS.length, browser_artifacts_removed: true };
      },
    }),
  );
  assert.equal(result.results.length, HEADER_IDS.length);
  assert.equal(result.success, false);
  assert.equal(result.cleanup.worker_artifacts_removed, false);
  const lock = JSON.parse(await readFile(join(root, 'receipts', 'active.lock'), 'utf8'));
  assert.equal(lock.state, 'recovery-required');
  const suiteReceipt = JSON.parse(await readFile(join(root, 'receipts', `suite-${result.run_id}.json`), 'utf8'));
  assert.equal(suiteReceipt.results.length, HEADER_IDS.length);
  assert.equal(suiteReceipt.cleanup.worker_artifacts_removed, false);
  const blocked = await status(config(root));
  assert.equal(blocked.active, true);
  assert.equal(blocked.state, 'recovery-required');
});

test('suite cleanup exception preserves completed results and recovery evidence', async () => {
  const root = await workspace();
  let cleanupCalls = 0;
  const result = await runSuite(
    config(root),
    deps({
      cleanup: async () => {
        cleanupCalls += 1;
        if (cleanupCalls > HEADER_IDS.length) throw new Error('cleanup token secret-not-for-receipts');
        return { worker_artifacts_removed: true, browser_artifacts_removed: true };
      },
    }),
  );
  assert.equal(result.results.length, HEADER_IDS.length);
  assert.equal(result.success, false);
  assert.equal(result.cleanup.worker_artifacts_removed, false);
  assert.equal(result.cleanup.error.code, 'CLEANUP_FAILED');
  assert.doesNotMatch(result.cleanup.error.message, /secret-not-for-receipts/);
  const lock = JSON.parse(await readFile(join(root, 'receipts', 'active.lock'), 'utf8'));
  assert.equal(lock.state, 'recovery-required');
  const receipt = JSON.parse(await readFile(join(root, 'receipts', `suite-${result.run_id}.json`), 'utf8'));
  assert.equal(receipt.results.length, HEADER_IDS.length);
  assert.equal(receipt.error.code, 'CLEANUP_FAILED');
});

test('bootstrap rejects drift and writes only after clean readiness and baseline', async () => {
  const root = await workspace();
  await assert.rejects(
    bootstrap(config(root), deps({ executor: executor({ driftCode: 2 }) })),
    (error) => error.code === 'DRIFT',
  );
  const result = await bootstrap(config(root), deps());
  assert.equal(result.success, true);
  const receipts = (await readdir(join(root, 'receipts'))).filter((name) => name.startsWith('bootstrap-'));
  assert.equal(receipts.length, 2);
  assert.equal(receipts.filter((name) => name.endsWith('-failed.json')).length, 1);
});

test('bootstrap emits repeated workstation and worker controls and gates all headers', async () => {
  const root = await workspace();
  let now = Date.parse(START);
  const locations = [];
  const polledHeaders = new Set();
  const result = await bootstrap(
    config(root, {
      timings: { ...config(root).timings, bootstrapControlMs: 3, quietMs: 0, pollMs: 1 },
    }),
    deps({
      probe: ({ headerId, location }) => {
        assert.equal(headerId, null);
        locations.push(location);
        return probe();
      },
      alertSource: async ({ headerId }) => {
        polledHeaders.add(headerId);
        return [];
      },
      now: () => new Date(now).toISOString(),
      nowMs: () => now,
      sleep: async (ms) => {
        now += ms;
      },
    }),
  );
  assert.equal(result.success, true);
  assert.ok(locations.filter((item) => item === 'workstation').length >= 3);
  assert.ok(locations.filter((item) => item === 'worker').length >= 3);
  assert.deepEqual([...polledHeaders].sort(), [...HEADER_IDS].sort());
});

test('bootstrap observes a full quiet period after a late firing alert', async () => {
  const root = await workspace();
  let now = Date.parse(START);
  let polls = 0;
  const result = await bootstrap(
    config(root, { timings: { ...config(root).timings, bootstrapControlMs: 1, quietMs: 3, pollMs: 1 } }),
    deps({
      alertSource: async ({ headerId }) => {
        polls += 1;
        if (headerId !== HEADER_IDS[0]) return [];
        if (polls === HEADER_IDS.length * 2 + 1)
          return [
            [
              alert(undefined, {
                labels: { ...alert().labels, header: HEADER_IDS[0] },
                startsAt: new Date(now).toISOString(),
              }),
            ],
          ];
        if (polls === HEADER_IDS.length * 3 + 1)
          return [
            [
              alert(undefined, {
                labels: { ...alert().labels, header: HEADER_IDS[0] },
                startsAt: new Date(now - 1).toISOString(),
                endsAt: new Date(now).toISOString(),
                status: 'resolved',
              }),
            ],
          ];
        return [];
      },
      now: () => new Date(now).toISOString(),
      nowMs: () => now,
      sleep: async (ms) => {
        now += ms;
      },
    }),
  );
  assert.equal(result.success, true);
  assert.ok(now - Date.parse(START) >= 4);
});

test('bootstrap requires explicit resolution after firing omission before quiet begins', async () => {
  const root = await workspace();
  let now = Date.parse(START);
  let round = 0;
  const firing = alert(undefined, {
    labels: { ...alert().labels, header: HEADER_IDS[0] },
    startsAt: START,
  });
  const resolved = {
    ...firing,
    status: 'resolved',
    endsAt: new Date(Date.parse(START) + 2).toISOString(),
  };
  const result = await bootstrap(
    config(root, { timings: { ...config(root).timings, bootstrapControlMs: 0, quietMs: 3, pollMs: 1 } }),
    deps({
      alertSource: async ({ headerId }) => {
        if (headerId !== HEADER_IDS[0]) return [];
        round += 1;
        if (round === 1) return [[firing]];
        if (round === 3) return [[resolved]];
        return [];
      },
      now: () => new Date(now).toISOString(),
      nowMs: () => now,
      sleep: async (ms) => {
        now += ms;
      },
    }),
  );
  assert.equal(result.success, true);
  assert.ok(now - Date.parse(START) >= 5);
  assert.deepEqual(
    result.alerts.map(({ state }) => state),
    ['firing', 'resolved'],
  );
});

test('bootstrap tracks an already-firing current alert until explicit history resolution', async () => {
  const root = await workspace();
  let now = Date.parse(START);
  let round = 0;
  const oldFiring = alert(undefined, {
    labels: { ...alert().labels, header: HEADER_IDS[0] },
    startsAt: new Date(now - 60_000).toISOString(),
  });
  const resolved = { ...oldFiring, status: 'resolved', endsAt: new Date(now + 2).toISOString() };
  const result = await bootstrap(
    config(root, { timings: { ...config(root).timings, bootstrapControlMs: 0, quietMs: 3, pollMs: 1 } }),
    deps({
      alertSource: async ({ headerId }) => {
        if (headerId !== HEADER_IDS[0]) return { current: [], history: [] };
        round += 1;
        if (round === 1) return { current: [oldFiring], history: [] };
        if (round === 3) return { current: [], history: [resolved] };
        return { current: [], history: [] };
      },
      now: () => new Date(now).toISOString(),
      nowMs: () => now,
      sleep: async (ms) => {
        now += ms;
      },
    }),
  );
  assert.equal(result.success, true);
  assert.ok(now - Date.parse(START) >= 5);
  assert.deepEqual(
    result.alerts.map(({ state }) => state),
    ['firing', 'resolved'],
  );
});

test('failed bootstrap attempts recovery, persists failure, and clears lock only after success', async () => {
  const root = await workspace();
  let readinessCalls = 0;
  const injected = deps({
    readiness: async () => {
      readinessCalls += 1;
      return readinessCalls === 1
        ? { endpoint_health: false }
        : {
            endpoint_health: true,
            payment_health: true,
            application_health: true,
            lb_ready: true,
            certificate_valid: true,
          };
    },
  });
  await assert.rejects(bootstrap(config(root), injected), (error) => error.code === 'READINESS_FAILED');
  assert.ok(readinessCalls >= 2);
  const files = await readdir(join(root, 'receipts'));
  assert.equal(files.includes('active.lock'), false);
  const failed = files.find((name) => name.startsWith('bootstrap-'));
  const receipt = JSON.parse(await readFile(join(root, 'receipts', failed), 'utf8'));
  assert.equal(receipt.success, false);
  assert.equal(receipt.recovery.success, true);
});

test('recovery emits repeated control pairs before final proof', async () => {
  const root = await workspace();
  let now = Date.parse(START);
  const locations = [];
  const result = await runHeader(
    config(root, { timings: { ...config(root).timings, recoveryMs: 3, pollMs: 1 } }),
    deps({
      probe: ({ headerId, location }) => {
        locations.push({ headerId, location, now });
        return probe({ headerId });
      },
      now: () => new Date(now).toISOString(),
      nowMs: () => now,
      sleep: async (ms) => {
        now += ms;
      },
    }),
    'x-content-type-options',
  );
  assert.equal(result.recovery.success, true);
  const recoveryControls = locations.filter(({ headerId }) => headerId === null);
  assert.ok(recoveryControls.filter(({ location }) => location === 'workstation').length >= 4);
  assert.ok(recoveryControls.filter(({ location }) => location === 'worker').length >= 4);
});

test('F5 token is environment-only and exact API origin is mandatory', async () => {
  const { parseArgs } = await import('../scripts/csd-page-tamper.mjs');
  assert.throws(() => parseArgs(['bootstrap', '--f5-api-token', 'secret'], {}), /unknown option/);
  const root = await workspace();
  await assert.rejects(
    validateDeploymentIdentity(config(root, { f5ApiUrl: 'https://other.console.ves.volterra.io' }), deps()),
    (error) => error.code === 'IDENTITY_MISMATCH',
  );
});

test('production worker keeps every current-source SSM command and parameters value within 4096 characters', async () => {
  const root = await workspace();
  const calls = [];
  const result = probe();
  let commandId = 0;
  const injected = deps({
    executor: async (argv) => {
      calls.push(argv);
      if (argv[2] === 'send-command')
        return {
          code: 0,
          stdout: JSON.stringify({ Command: { CommandId: `cmd-${++commandId}` } }),
          stderr: '',
        };
      if (argv[2] === 'get-command-invocation')
        return {
          code: 0,
          stdout: JSON.stringify({
            Status: 'Success',
            ResponseCode: 0,
            StandardOutputContent: `XCSH_RESULT ${JSON.stringify(result)}\n`,
            StandardErrorContent: '',
          }),
          stderr: '',
        };
      throw new Error('unexpected');
    },
    nowMs: (() => {
      let value = 0;
      return () => (value += 100);
    })(),
  });
  assert.deepEqual(await runWorkerProbe(config(root), injected, 'x-frame-options'), result);
  assert.ok(calls.every(Array.isArray));
  const sendCalls = calls.filter((argv) => argv[2] === 'send-command');
  const parameters = sendCalls.map((argv) => argv[argv.indexOf('--parameters') + 1]);
  const commands = parameters.flatMap((value) => JSON.parse(value).commands);
  const maxCommand = Math.max(...commands.map((value) => value.length));
  const maxParameters = Math.max(...parameters.map((value) => value.length));
  assert.ok(sendCalls.length >= 5, 'expected init, chunks, extraction, probe, and cleanup commands');
  assert.ok(commands.some((value) => value.includes('sha256sum')));
  assert.ok(commands.some((value) => value.includes('base64 -d')));
  assert.ok(commands.some((value) => value.includes('sudo -u ubuntu -H')));
  assert.ok(commands.some((value) => value.includes("rm -rf '/tmp/xcsh-csd-")));
  const encodedWorkerScript = commands
    .map((value) => value.match(/printf %s '([^']+)' >>'[^']+\.launch-[^']+\.b64'/)?.[1])
    .filter(Boolean)
    .join('');
  assert.ok(encodedWorkerScript, 'expected encoded worker launcher chunks');
  const workerScript = Buffer.from(encodedWorkerScript, 'base64').toString();
  assert.match(workerScript, /for c in \/opt\/node\/bin\/node node/);
  assert.match(workerScript, /node_bin=.*\$node_bin/);
  assert.match(workerScript, /\[ -n "\$node_bin" \]\|\|exit 36/);
  assert.match(workerScript, /"\$node_bin" -e/);
  assert.match(workerScript, /"\$node_bin" "\$probe\/entry\.mjs"/);
  assert.ok(maxCommand <= 4096, `maximum command was ${maxCommand}`);
  assert.ok(maxParameters <= 4096, `maximum parameters value was ${maxParameters}`);
  const serialized = JSON.stringify(calls);
  assert.match(serialized, /\/tmp\/xcsh-csd-/);
  assert.doesNotMatch(serialized, /secret-not-for-receipts|APIToken|Cookie|Authorization/);
  assert.doesNotMatch(serialized, /pgrep/);
  assert.match(workerScript, /\[ -x \/usr\/bin\/setsid \]\|\|exit 37/);
  assert.match(workerScript, /\/usr\/bin\/setsid --fork "\$spawn" "\$pidfile"/);
  assert.match(workerScript, /printf '%s %s\\n' "\$pid" "\$pgid" >"\$pidfile";exec "\$@"/);
  assert.match(
    workerScript,
    /if \[ "\$pid" = "\$launcher_pid" \]\|\|\[ "\$pid" = "\$launcher_pgid" \]\|\|\[ "\$pgid" = "\$launcher_pid" \]\|\|\[ "\$pgid" = "\$launcher_pgid" \];then exit 39/,
  );
  assert.match(workerScript, /case "\$pid:\$pgid" in :\*\|\*:\|\*\[!0-9:\]\*\|0:\*\|\*:0/);
  assert.match(workerScript, /kill -TERM -- "-\$pgid".*kill -TERM "\$pid"/);
  assert.match(workerScript, /kill -KILL -- "-\$pgid".*kill -KILL "\$pid"/);
  assert.match(workerScript, /while alive&&\[ "\$i" -lt 5 \]/);
  assert.match(workerScript, /while \[ "\$i" -lt 5 \]&&\[ -e "\$probe" \]/);
  assert.doesNotMatch(workerScript, /(?:^|;)wait(?: |;)/);
  assert.doesNotMatch(serialized, /--no-sandbox/);
  process.stdout.write(`MAX_SSM_COMMAND=${maxCommand} MAX_SSM_PARAMETERS=${maxParameters}\n`);
});

test('alert polling accumulates Modified evidence and performs a deadline poll', async () => {
  const root = await workspace();
  let polls = 0;
  let now = Date.parse(START);
  const result = await runHeader(
    config(root, { timings: { ...config(root).timings, mixedMs: 2, maximumCaseMs: 2, pollMs: 1 } }),
    deps({
      alertSource: async () => {
        polls += 1;
        return polls === 1 ? [[alert('ClientSideDefenseHttpHeaderModified')]] : [];
      },
      now: () => new Date(now).toISOString(),
      nowMs: () => now,
      sleep: async (ms) => {
        now += ms;
      },
    }),
    'x-content-type-options',
  );
  assert.equal(result.outcome, 'MODIFIED_ONLY');
  assert.equal(result.phases.mixed.final_poll, true);
  assert.ok(polls >= 2);
});

test('production object polling accumulates current and history without duplicate alerts', async () => {
  const root = await workspace();
  let polls = 0;
  let now = Date.parse(START);
  const firing = alert('ClientSideDefenseHttpHeaderModified');
  const result = await runHeader(
    config(root, { timings: { ...config(root).timings, mixedMs: 2, maximumCaseMs: 2, pollMs: 1 } }),
    deps({
      alertSource: async () => {
        polls += 1;
        return polls === 1 ? { current: [firing], history: [] } : { current: [], history: [firing] };
      },
      now: () => new Date(now).toISOString(),
      nowMs: () => now,
      sleep: async (ms) => {
        now += ms;
      },
    }),
    'x-content-type-options',
  );
  assert.equal(result.outcome, 'MODIFIED_ONLY');
  assert.equal(result.phases.mixed.final_poll, true);
  assert.ok(polls >= 2);
  assert.equal(result.alerts.length, 1);
  assert.equal(result.alerts[0].alert_name, 'ClientSideDefenseHttpHeaderModified');
});

test('status exposes evidence persistence failure as recovery-required', async () => {
  const root = await workspace();
  await mkdir(join(root, 'receipts'), { recursive: true });
  await writeFile(
    join(root, 'receipts', 'active.lock'),
    JSON.stringify({
      run_id: 'failed',
      started_at: START,
      state: 'recovery-required',
      evidence_persistence_failure: true,
    }),
  );
  const result = await status(config(root));
  assert.equal(result.active, true);
  assert.equal(result.interrupted, true);
  assert.equal(result.evidence_persistence_failure, true);
});

test('no-drift uses a normal refresh-aware Terraform plan', async () => {
  const root = await workspace();
  const calls = [];
  await bootstrap(
    config(root),
    deps({
      executor: async (argv, options) => {
        calls.push(argv);
        return executor()(argv, options);
      },
    }),
  );
  const plans = calls.filter((argv) => argv.includes('plan'));
  assert.ok(plans.length >= 1);
  assert.ok(plans.every((argv) => argv.includes('-detailed-exitcode')));
  assert.ok(plans.every((argv) => !argv.includes('-refresh-only')));
});

test('same-host dead recovery owner is reclaimed before stale timeout', async () => {
  const root = await workspace();
  const receiptDir = join(root, 'receipts');
  const claimDir = join(receiptDir, 'recovery.claim');
  await mkdir(claimDir, { recursive: true });
  await writeFile(
    join(claimDir, 'owner.json'),
    JSON.stringify({
      claim_id: 'dead-owner',
      run_id: 'original-run',
      claimed_at: START,
      hostname: 'test-host',
      pid: 4242,
    }),
  );
  await writeFile(
    join(receiptDir, 'active.lock'),
    JSON.stringify({ run_id: 'original-run', command: 'run', started_at: START, state: 'recovery-required' }),
  );
  const result = await runHeader(
    config(root, { timings: { ...config(root).timings, maximumCaseMs: 60 * 60_000 } }),
    deps({ hostname: () => 'test-host', pid: () => 5000, isProcessAlive: (pid) => pid !== 4242 }),
    'x-content-type-options',
  );
  assert.equal(result.recovery.success, true);
  await assert.rejects(stat(claimDir), /ENOENT/);
});

test('live, foreign, and legacy recovery owners remain age-gated', async () => {
  for (const owner of [
    { hostname: 'test-host', pid: 4242 },
    { hostname: 'foreign-host', pid: 4242 },
    { hostname: 'test-host' },
  ]) {
    const root = await workspace();
    const receiptDir = join(root, 'receipts');
    const claimDir = join(receiptDir, 'recovery.claim');
    await mkdir(claimDir, { recursive: true });
    await writeFile(
      join(claimDir, 'owner.json'),
      JSON.stringify({ claim_id: 'owner', run_id: 'original-run', claimed_at: START, ...owner }),
    );
    await writeFile(
      join(receiptDir, 'active.lock'),
      JSON.stringify({ run_id: 'original-run', command: 'run', started_at: START, state: 'recovery-required' }),
    );
    await assert.rejects(
      runHeader(
        config(root, { timings: { ...config(root).timings, maximumCaseMs: 60 * 60_000 } }),
        deps({ hostname: () => 'test-host', isProcessAlive: () => true }),
        'x-content-type-options',
      ),
      (error) => error.code === 'OVERLAP',
    );
  }
});
