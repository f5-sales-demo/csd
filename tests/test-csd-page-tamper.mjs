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
  cleanupWorker,
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
  awsProfile: '280469140135_Users',
  awsRegion: 'us-east-1',
  namespace: 'client-side-defense',
  lbName: 'client-side-defense',
  terraformDir: join(root, 'terraform'),
  trafficGeneratorTerraformDir: join(root, 'traffic-generator-aws'),
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
  await mkdir(join(root, 'traffic-generator-aws'), { recursive: true });
  await writeFile(
    join(root, 'terraform', 'versions.tf'),
    'terraform {\n  backend "s3" {\n    bucket = "terraform-tfstate-xc"\n    key = "f5-sales-demo/client-side-defense.tfstate"\n  }\n}\n',
  );
  await writeFile(
    join(root, 'traffic-generator-aws', 'versions.tf'),
    'terraform {\n  backend "s3" {\n    bucket = "terraform-tfstate-xc"\n    key = "f5-sales-demo/traffic-generator-aws.tfstate"\n    region = "us-east-1"\n  }\n}\n',
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

function executor({ driftCode = 0, workerInstance = 'i-0123456789abcdef0' } = {}) {
  return async (argv) => {
    if (argv[0] === 'aws' && argv[1] === 'sts')
      return { code: 0, stdout: JSON.stringify({ Account: '280469140135' }), stderr: '' };
    if (argv[0] === 'aws' && argv[1] === 'ec2')
      return {
        code: 0,
        stdout: JSON.stringify({
          Reservations: [{ Instances: [{ InstanceId: workerInstance, State: { Name: 'running' } }] }],
        }),
        stderr: '',
      };
    if (argv[0] === 'terraform' && argv.includes('-raw')) return { code: 0, stdout: `${workerInstance}\n`, stderr: '' };
    if (argv[0] === 'terraform' && argv.includes('-json'))
      return { code: 0, stdout: JSON.stringify(outputs), stderr: '' };
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
      path: 'https://client-side-defense.f5-sales-demo.com/csd-page-tamper/payment',
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

test('worker identity comes only from the reviewed traffic-generator Terraform output', async () => {
  const root = await workspace();
  const calls = [];
  const injected = deps({
    executor: async (argv, options) => {
      calls.push(argv);
      return executor()(argv, options);
    },
  });
  const runtimeConfig = config(root);
  await validateDeploymentIdentity(runtimeConfig, injected);
  assert.equal(runtimeConfig.workerInstance, 'i-0123456789abcdef0');
  const workerOutput = calls.find(
    (argv) => argv[0] === 'terraform' && argv.includes('-raw') && argv.includes('instance_id'),
  );
  assert.deepEqual(workerOutput, [
    'terraform',
    `-chdir=${runtimeConfig.trafficGeneratorTerraformDir}`,
    'output',
    '-raw',
    'instance_id',
  ]);
  assert.equal(calls.findIndex((argv) => argv.includes('-raw')) < calls.findIndex((argv) => argv[1] === 'ec2'), true);
});

test('worker output mismatch and missing output fail closed before SSM', async () => {
  const root = await workspace();
  const mismatchCalls = [];
  const mismatch = deps({
    executor: async (argv, options) => {
      mismatchCalls.push(argv);
      if (argv[0] === 'terraform' && argv.includes('-raw'))
        return { code: 0, stdout: 'i-aaaaaaaaaaaaaaaaa\n', stderr: '' };
      return executor()(argv, options);
    },
  });
  await assert.rejects(
    validateDeploymentIdentity(config(root), mismatch),
    (error) => error.code === 'IDENTITY_MISMATCH',
  );
  const describe = mismatchCalls.find((argv) => argv[1] === 'ec2');
  assert.equal(describe[describe.indexOf('--instance-ids') + 1], 'i-aaaaaaaaaaaaaaaaa');
  assert.equal(
    mismatchCalls.some((argv) => argv[1] === 'ssm'),
    false,
  );

  const missingCalls = [];
  const missing = deps({
    executor: async (argv) => {
      missingCalls.push(argv);
      return { code: 0, stdout: '', stderr: '' };
    },
  });
  await assert.rejects(
    validateDeploymentIdentity(config(root), missing),
    (error) => error.code === 'WORKER_IDENTITY_INVALID',
  );
  assert.equal(missingCalls.length, 1);
  assert.equal(missingCalls[0].includes('-raw'), true);
});

test('traffic-generator Terraform backend mismatch blocks output lookup', async () => {
  const root = await workspace();
  const runtimeConfig = config(root);
  await writeFile(
    join(runtimeConfig.trafficGeneratorTerraformDir, 'versions.tf'),
    'terraform {\n  backend "s3" {\n    bucket = "wrong-bucket"\n    key = "f5-sales-demo/traffic-generator-aws.tfstate"\n    region = "us-east-1"\n  }\n}\n',
  );
  let commands = 0;
  await assert.rejects(
    validateDeploymentIdentity(
      runtimeConfig,
      deps({
        executor: async () => {
          commands++;
          return { code: 0, stdout: '', stderr: '' };
        },
      }),
    ),
    (error) => error.code === 'IDENTITY_MISMATCH',
  );
  assert.equal(commands, 0);
});

test('history JSON strings parse and exact current/history matches dedupe', () => {
  const expected = {
    namespace: 'client-side-defense',
    origin: 'https://client-side-defense.f5-sales-demo.com',
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
test('JSON encoded alert in unrelated description cannot become Page Tamper proof', () => {
  const expected = {
    namespace: 'client-side-defense',
    origin: 'https://client-side-defense.f5-sales-demo.com',
    path: '/csd-page-tamper/payment',
    headerId: 'x-content-type-options',
    windowStart: START,
    windowEnd: '2026-09-25T12:01:00.000Z',
  };
  const decoy = alert('UnrelatedAlert', { description: JSON.stringify(alert()) });
  assert.deepEqual(correlateAlertViews({ current: [decoy], history: [] }, expected), []);
  assert.deepEqual(correlateAlertViews({ current: [], history: [JSON.stringify(decoy)] }, expected), []);
  const history = JSON.stringify({ '@timestamp': START, alerts: [JSON.stringify(alert())] });
  assert.equal(correlateAlertViews({ current: [], history: [history] }, expected).length, 1);
  assert.equal(
    correlateAlertViews({ current: [{ data: JSON.stringify([alert()]) }], history: [] }, expected).length,
    1,
  );
});

test('current firing alerts may predate bootstrap while stale resolved history remains excluded', () => {
  const expected = {
    namespace: 'client-side-defense',
    origin: 'https://client-side-defense.f5-sales-demo.com',
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
    origin: 'https://client-side-defense.f5-sales-demo.com',
    path: '/csd-page-tamper/payment',
    headerId: 'x-content-type-options',
    windowStart: '2026-09-25T11:59:00.000Z',
    windowEnd: '2026-09-25T12:01:00.000Z',
  };
  const invalid = [
    alert('OtherAlert'),
    alert(undefined, { labels: { ...alert().labels, path: 'https://client-side-defense.f5-sales-demo.com/other' } }),
    alert(undefined, { labels: { ...alert().labels, path: 'https://other.example/csd-page-tamper/payment' } }),
    alert(undefined, {
      labels: { ...alert().labels, path: 'http://client-side-defense.f5-sales-demo.com/csd-page-tamper/payment' },
    }),
    alert(undefined, { labels: { ...alert().labels, path: '/csd-page-tamper/payment' } }),
    alert(undefined, { labels: { ...alert().labels, path: 'not a URL' } }),
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

test('historical Modified live-format event matches exact origin, header list and nanoseconds', () => {
  const expected = {
    namespace: 'client-side-defense',
    origin: 'https://client-side-defense.f5-sales-demo.com',
    path: '/csd-page-tamper/payment',
    headerId: 'x-content-type-options',
    windowStart: '2026-09-25T11:59:00.000Z',
    windowEnd: '2026-09-25T12:01:00.000Z',
  };
  const raw = alert('ClientSideDefenseHttpHeaderModified', {
    labels: {
      ...alert('ClientSideDefenseHttpHeaderModified').labels,
      header: 'x-content-type-options, x-frame-options, cache-control',
    },
    startsAt: '2026-09-25T12:00:00.123456789Z',
  });
  const matches = correlateAlertViews({ current: [], history: [JSON.stringify(raw)] }, expected);
  assert.equal(matches.length, 1);
  assert.equal(matches[0].starts_at, '2026-09-25T12:00:00.123Z');
  assert.equal(classifyAlerts(matches), 'MODIFIED_ONLY');
});

test('live firing sentinel stays open until a real resolved history event', () => {
  const expected = {
    namespace: 'client-side-defense',
    origin: 'https://client-side-defense.f5-sales-demo.com',
    path: '/csd-page-tamper/payment',
    headerId: 'x-content-type-options',
    windowStart: '2026-09-25T11:59:00.000Z',
    windowEnd: '2026-09-25T12:01:00.000Z',
  };
  const firing = alert('ClientSideDefenseHttpHeaderModified', {
    labels: { ...alert().labels, header: 'x-content-type-options, x-frame-options, cache-control' },
    startsAt: '2026-09-25T11:58:00.123456789Z',
    status: 'firing',
    endsAt: '0001-01-01T00:00:00Z',
  });
  const resolved = { ...firing, status: 'resolved', endsAt: '2026-09-25T12:00:30.000Z' };
  const views = { current: [firing], history: [JSON.stringify(resolved)] };
  assert.deepEqual(
    correlateAlertViews(views, expected).map(({ state, ends_at }) => [state, ends_at]),
    [['firing', null]],
  );
  assert.deepEqual(
    correlateAlertViews(views, expected, { allowPriorResolution: true }).map(({ state, ends_at }) => [state, ends_at]),
    [
      ['firing', null],
      ['resolved', '2026-09-25T12:00:30.000Z'],
    ],
  );
  assert.deepEqual(
    correlateAlertViews({ current: [{ ...firing, status: undefined }], history: [] }, expected).map(
      ({ state, ends_at }) => [state, ends_at],
    ),
    [['firing', null]],
  );
  assert.deepEqual(
    correlateAlertViews({ current: [], history: [{ ...resolved, status: undefined }] }, expected, {
      allowPriorResolution: true,
    }).map(({ state, ends_at }) => [state, ends_at]),
    [['resolved', '2026-09-25T12:00:30.000Z']],
  );
  assert.deepEqual(correlateAlertViews({ current: [{ ...firing, status: 'unknown' }], history: [] }, expected), []);
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

test('bounded campaign rejects old matching current firing without manufacturing alert proof', async () => {
  const old = alert(undefined, { startsAt: '2026-09-25T11:59:59.999Z', endsAt: '0001-01-01T00:00:00Z' });
  const resolved = { ...old, status: 'resolved', endsAt: '2026-09-25T11:59:59.999Z' };
  for (const current of [[old], []]) {
    const root = await workspace();
    const result = await runHeader(
      config(root, { timings: { ...config(root).timings, mixedMs: 2, pollMs: 1 } }),
      deps({
        alertSource: async () => ({
          current: [
            ...current,
            alert(undefined, {
              labels: { ...alert().labels, path: 'https://other.example/csd-page-tamper/payment' },
              startsAt: old.startsAt,
            }),
            alert(undefined, { labels: { ...alert().labels, header: 'x-frame-options' }, startsAt: old.startsAt }),
            alert(undefined, {
              labels: { ...alert().labels, path: 'https://client-side-defense.f5-sales-demo.com/other' },
              startsAt: old.startsAt,
            }),
            alert(undefined, { labels: { ...alert().labels, namespace: 'other' }, startsAt: old.startsAt }),
          ],
          history: [resolved],
        }),
      }),
      'x-content-type-options',
    );
    assert.equal(result.outcome, current.length ? 'INVALID_TEST' : 'NO_ALERT_WITHIN_WINDOW');
    assert.equal(result.recovery.success, true);
    assert.deepEqual(result.alerts, []);
    if (current.length) assert.equal(result.error.code, 'INVALID_TEST');
  }
});

test('bounded campaign accepts in-window current and history once', async () => {
  const root = await workspace();
  const event = alert(undefined, { endsAt: '0001-01-01T00:00:00Z' });
  const result = await runHeader(
    config(root, { timings: { ...config(root).timings, mixedMs: 2, pollMs: 1 } }),
    deps({ alertSource: async () => ({ current: [event], history: [event] }) }),
    'x-content-type-options',
  );
  assert.equal(result.outcome, 'COMPROMISED');
  assert.equal(result.alerts.length, 1);
  assert.equal(result.alerts[0].starts_at, START);
});

test('bounded telemetry exception remains INVALID_TEST rather than a no-alert result', async () => {
  const root = await workspace();
  const result = await runHeader(
    config(root, { timings: { ...config(root).timings, mixedMs: 2, pollMs: 1 } }),
    deps({
      alertSource: async () => {
        throw new ControllerError('alert polling failed', 'TELEMETRY_GAP');
      },
    }),
    'x-content-type-options',
  );
  assert.equal(result.outcome, 'INVALID_TEST');
  assert.equal(result.error.code, 'TELEMETRY_GAP');
  assert.deepEqual(result.alerts, []);
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
    JSON.stringify({
      run_id: 'original-run',
      command: 'run',
      started_at: START,
      state: 'recovery-required',
      worker_run_id: null,
    }),
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
    JSON.stringify({
      run_id: 'original-run',
      command: 'run',
      started_at: START,
      state: 'recovery-required',
      worker_run_id: null,
    }),
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
    JSON.stringify({
      run_id: 'original-run',
      command: 'run',
      started_at: START,
      state: 'recovery-required',
      worker_run_id: null,
    }),
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
          new URL(url).pathname.endsWith('/history')
            ? { alerts: [JSON.stringify(resolvedAlert)], total_hits: '1', scroll_id: '' }
            : { data: JSON.stringify([currentAlert]) },
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
          json: async () =>
            new URL(url).pathname.endsWith('/history')
              ? { alerts: [], total_hits: '0', scroll_id: 'stable-zero-hit-cursor' }
              : { data: JSON.stringify([currentAlert]) },
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
  assert.ok(urls.some((url) => new URL(url).pathname.endsWith('/alerts') && !new URL(url).search));
  for (const state of ['inactive', 'silenced', 'inhibited', 'unprocessed'])
    assert.ok(urls.some((url) => new URL(url).searchParams.get(state) === 'true'));
  assert.ok(
    urls.some((url) => {
      const parsed = new URL(url);
      return (
        parsed.pathname.endsWith('/alerts/history') &&
        parsed.searchParams.get('start_time') === START &&
        parsed.searchParams.has('end_time')
      );
    }),
  );
  assert.equal(
    urls.some((url) => new URL(url).pathname.endsWith('/history/scroll')),
    false,
  );
});

test('production history scroll reconciles 501 hits and stops despite a remaining cursor', async () => {
  const root = await workspace();
  let now = Date.parse(START);
  const urls = [];
  const record = JSON.stringify(alert('ClientSideDefenseHttpHeaderModified'));
  const result = await bootstrap(
    config(root, { timings: { ...config(root).timings, bootstrapControlMs: 1, quietMs: 0, pollMs: 1 } }),
    deps({
      alertSource: null,
      fetch: async (url, options) => {
        urls.push(url);
        assert.equal(options.headers.Authorization, 'APIToken secret-not-for-receipts');
        const path = new URL(url).pathname;
        const body = path.endsWith('/history/scroll')
          ? { alerts: [record], total_hits: '501', scroll_id: 'still-present' }
          : path.endsWith('/history')
            ? { alerts: Array(500).fill(record), total_hits: '501', scroll_id: 'next-page' }
            : { data: '[]' };
        return { ok: true, json: async () => body };
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
  const scroll = urls.filter((url) => new URL(url).pathname.endsWith('/history/scroll'));
  assert.equal(scroll.length, 1);
  assert.equal(new URL(scroll[0]).searchParams.get('scroll_id'), 'next-page');
});

test('production telemetry fails closed on incomplete, repeated, malformed and HTTP error pages', async () => {
  for (const failure of ['missing-cursor', 'repeated-cursor', 'bad-total', 'bad-record', 'bad-current', 'http-error']) {
    const root = await workspace();
    let now = Date.parse(START);
    let scrollCalls = 0;
    await assert.rejects(
      bootstrap(
        config(root, { timings: { ...config(root).timings, bootstrapControlMs: 1, quietMs: 0, pollMs: 1 } }),
        deps({
          alertSource: null,
          fetch: async (url) => {
            const path = new URL(url).pathname;
            if (path.endsWith('/history/scroll')) scrollCalls += 1;
            if (failure === 'http-error' && path.endsWith('/history')) return { ok: false };
            const body = path.endsWith('/history/scroll')
              ? { alerts: [JSON.stringify(alert())], total_hits: '3', scroll_id: 'same' }
              : path.endsWith('/history')
                ? failure === 'bad-total'
                  ? { alerts: [], total_hits: 'invalid', scroll_id: '' }
                  : failure === 'bad-record'
                    ? { alerts: ['not json'], total_hits: '1', scroll_id: '' }
                    : {
                        alerts: [JSON.stringify(alert())],
                        total_hits: '3',
                        scroll_id: failure === 'missing-cursor' ? '' : 'same',
                      }
                : { data: failure === 'bad-current' ? '{invalid' : '[]' };
            return { ok: true, json: async () => body };
          },
          sleep: async (ms) => {
            now += ms;
          },
          now: () => new Date(now).toISOString(),
          nowMs: () => now,
        }),
      ),
      (error) => error instanceof ControllerError && error.code === 'TELEMETRY_GAP',
      failure,
    );
    assert.equal(scrollCalls, failure === 'repeated-cursor' ? 1 : 0, failure);
  }
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

test('bootstrap retains lock after production SSM final cleanup fails despite successful earlier recovery', async () => {
  const root = await workspace();
  const base = executor();
  let cleanupCommands = 0;
  let lastCommand = '';
  let readinessCalls = 0;
  const injected = deps({
    workerProbe: null,
    executor: async (argv, options) => {
      if (argv[0] !== 'aws' || argv[1] !== 'ssm') return base(argv, options);
      if (argv[2] === 'send-command') {
        const parameters = argv[argv.indexOf('--parameters') + 1];
        assert.ok(parameters.length <= 4096);
        lastCommand = JSON.parse(parameters).commands[0];
        if (lastCommand.includes('shutil.rmtree(root)')) cleanupCommands += 1;
        return { code: 0, stdout: JSON.stringify({ Command: { CommandId: 'command-1' } }), stderr: '' };
      }
      if (argv[2] === 'get-command-invocation')
        return {
          code: 0,
          stdout: JSON.stringify({
            Status: cleanupCommands ? 'Failed' : 'Success',
            ResponseCode: cleanupCommands ? 1 : 0,
          }),
          stderr: '',
        };
      throw new Error(`unexpected SSM operation: ${argv[2]}`);
    },
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
  assert.ok(cleanupCommands > 0);
  const receiptName = (await readdir(join(root, 'receipts'))).find((name) => name.startsWith('bootstrap-'));
  const receipt = JSON.parse(await readFile(join(root, 'receipts', receiptName), 'utf8'));
  assert.equal(receipt.success, false);
  assert.equal(receipt.recovery.success, false);
  assert.equal(receipt.recovery.cleanup.worker_artifacts_removed, false);
  const lock = JSON.parse(await readFile(join(root, 'receipts', 'active.lock'), 'utf8'));
  assert.equal(lock.state, 'recovery-required');
  assert.equal(lock.recovery_completed, false);
  assert.equal(lock.evidence_persistence_failure, false);
  assert.equal(lock.error.code, 'RECOVERY_FAILED');
  assert.equal((await status(config(root))).active, true);
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

const ownedWorker = (name = '00000000-0000-4000-8000-000000000004') => ({
  runId: name,
  root: `/tmp/xcsh-csd-${name}`,
  instance_id: 'i-0123456789abcdef0',
  aws_account: '280469140135',
  aws_region: 'us-east-1',
  aws_profile: '280469140135_Users',
});

function simulatedSsm(onScript, result = probe()) {
  const base = executor();
  let commandId = 0;
  let pendingFailure = false;
  return async (argv, options) => {
    if (argv[1] !== 'ssm') return base(argv, options);
    if (argv[2] === 'send-command') {
      const script = JSON.parse(argv[argv.indexOf('--parameters') + 1]).commands[0];
      pendingFailure = (await onScript(script)) === true;
      return { code: 0, stdout: JSON.stringify({ Command: { CommandId: `cmd-${++commandId}` } }), stderr: '' };
    }
    if (argv[2] === 'get-command-invocation')
      return {
        code: 0,
        stdout: JSON.stringify({
          Status: pendingFailure ? 'Failed' : 'Success',
          ResponseCode: pendingFailure ? 42 : 0,
          StandardOutputContent: `XCSH_RESULT ${JSON.stringify(result)}\n`,
        }),
        stderr: '',
      };
    throw new Error(`unexpected SSM operation ${argv[2]}`);
  };
}

test('worker-enabled CLI receipts, status, stdout, and active lock omit raw identities', async () => {
  const { main, parseArgs } = await import('../scripts/csd-page-tamper.mjs');
  const root = await workspace();
  const configValue = config(root);
  const env = {
    AWS_PROFILE: configValue.awsProfile,
    AWS_REGION: configValue.awsRegion,
    XCSH_CSD_AWS_ACCOUNT: configValue.awsAccount,
    XCSH_CSD_TERRAFORM_DIR: configValue.terraformDir,
    XCSH_CSD_TRAFFIC_GENERATOR_TERRAFORM_DIR: configValue.trafficGeneratorTerraformDir,
    XCSH_API_URL: configValue.f5ApiUrl,
    XCSH_API_TOKEN: 'secret-not-for-receipts',
    XCSH_NAMESPACE: configValue.namespace,
    XCSH_LB_NAME: configValue.lbName,
    XCSH_CSD_PAGE_TAMPER_RECEIPT_DIR: configValue.receiptDir,
  };
  assert.throws(() => parseArgs(['run', '--worker-instance', 'i-0123456789abcdef0'], env), /unknown option/);
  const parsed = parseArgs(['status'], env);
  assert.equal(parsed.config.receiptDir, configValue.receiptDir);
  assert.equal(Object.hasOwn(parsed.config, 'workerInstance'), false);

  const commands = [];
  let lockSnapshot;
  let statusSnapshot;
  const base = executor();
  const ssm = simulatedSsm(async () => {
    if (!lockSnapshot) {
      lockSnapshot = JSON.parse(await readFile(join(configValue.receiptDir, 'active.lock'), 'utf8'));
      statusSnapshot = await status(configValue);
    }
    return false;
  });
  let clock = Date.parse(START);
  let sequence = 0;
  let stdout = '';
  const exitCode = await main(
    [
      'run',
      '--header',
      'x-content-type-options',
      '--aws-profile',
      configValue.awsProfile,
      '--aws-region',
      configValue.awsRegion,
      '--aws-account',
      configValue.awsAccount,
      '--terraform-dir',
      configValue.terraformDir,
      '--traffic-generator-terraform-dir',
      configValue.trafficGeneratorTerraformDir,
      '--f5-api-url',
      configValue.f5ApiUrl,
      '--namespace',
      configValue.namespace,
      '--lb-name',
      configValue.lbName,
      '--receipt-dir',
      configValue.receiptDir,
    ],
    {
      env,
      stdout: {
        write: (value) => {
          stdout += value;
        },
      },
      stderr: { write: () => {} },
      workerProbe: null,
      executor: async (argv, options) => {
        commands.push(argv);
        return argv[1] === 'ssm' ? ssm(argv, options) : base(argv, options);
      },
      probe,
      readiness: async () => ({
        endpoint_health: true,
        payment_health: true,
        application_health: true,
        lb_ready: true,
        certificate_valid: true,
      }),
      alertSource: async () => [],
      sleep: async (ms) => {
        clock += ms;
      },
      now: () => new Date(clock).toISOString(),
      nowMs: () => clock,
      randomUUID: () => `00000000-0000-4000-8000-${String(++sequence).padStart(12, '0')}`,
    },
  );
  assert.equal(exitCode, 0);
  const output = JSON.parse(stdout);
  assert.ok(lockSnapshot);
  assert.ok(statusSnapshot.active);
  for (const serialized of [JSON.stringify(lockSnapshot), JSON.stringify(statusSnapshot), stdout]) {
    assert.doesNotMatch(serialized, /i-0123456789abcdef0|280469140135|280469140135_Users|secret-not-for-receipts/);
    assert.doesNotMatch(serialized, /"worker"|"instance_id"|"aws_account"|"aws_profile"|"hostname"|"pid"/);
  }
  assert.equal(lockSnapshot.worker_run_id, output.worker_run_id);
  assert.equal(Object.hasOwn(output, 'worker'), false);
  assert.equal(
    commands.findIndex((argv) => argv[0] === 'terraform' && argv.includes('-raw')) <
      commands.findIndex((argv) => argv[1] === 'ssm'),
    true,
  );
  const receiptName = (await readdir(configValue.receiptDir)).find((name) => name.endsWith('.json'));
  const receipt = JSON.parse(await readFile(join(configValue.receiptDir, receiptName), 'utf8'));
  const receiptJson = JSON.stringify(receipt);
  assert.doesNotMatch(receiptJson, /i-0123456789abcdef0|280469140135|280469140135_Users|secret-not-for-receipts/);
  assert.equal(Object.hasOwn(receipt, 'worker'), false);
});

test('suite resolves its worker output before SSM worker preparation', async () => {
  const root = await workspace();
  const calls = [];
  const base = executor();
  const ssm = simulatedSsm(async () => false);
  const injected = deps({
    workerProbe: null,
    executor: async (argv, options) => {
      calls.push(argv);
      return argv[1] === 'ssm' ? ssm(argv, options) : base(argv, options);
    },
    alertSource: async () => [],
  });
  const receipt = await runSuite(config(root), injected);
  const resolveIndex = calls.findIndex((argv) => argv[0] === 'terraform' && argv.includes('-raw'));
  const firstSsmIndex = calls.findIndex((argv) => argv[1] === 'ssm');
  assert.ok(resolveIndex >= 0 && resolveIndex < firstSsmIndex);
  assert.equal(receipt.worker_run_id, '00000000-0000-4000-8000-000000000001');
  assert.equal(Object.hasOwn(receipt, 'worker'), false);
  const suiteReceipt = JSON.parse(await readFile(join(root, 'receipts', `suite-${receipt.run_id}.json`), 'utf8'));
  assert.equal(suiteReceipt.worker_run_id, receipt.worker_run_id);
  assert.equal(Object.hasOwn(suiteReceipt, 'worker'), false);
  assert.doesNotMatch(JSON.stringify(suiteReceipt), /i-0123456789abcdef0|280469140135_Users/);
});

test('bootstrap records original worker root before first SSM command, including failed creation', async () => {
  const root = await workspace();
  const base = executor();
  let seen = 0;
  const injected = deps({
    workerProbe: null,
    executor: async (argv, options) => {
      if (argv[1] !== 'ssm') return base(argv, options);
      if (argv[2] === 'send-command') {
        const lock = JSON.parse(await readFile(join(root, 'receipts', 'active.lock'), 'utf8'));
        assert.equal(lock.worker_run_id, ownedWorker('00000000-0000-4000-8000-000000000001').runId);
        assert.equal(Object.hasOwn(lock, 'worker'), false);
        seen++;
        return { code: 1, stdout: '', stderr: '' };
      }
      throw new Error('unexpected SSM operation');
    },
  });
  await assert.rejects(bootstrap(config(root), injected), (error) => error.code === 'EXTERNAL_COMMAND_FAILED');
  assert.ok(seen >= 1);
  assert.equal(JSON.parse(await readFile(join(root, 'receipts', 'active.lock'), 'utf8')).state, 'recovery-required');
});

test('bootstrap partial preparation retains recorded root without starting fresh probes', async () => {
  const root = await workspace();
  const scripts = [];
  let probes = 0;
  const result = deps({
    workerProbe: null,
    cleanup: null,
    executor: simulatedSsm((script) => {
      scripts.push(script);
      return scripts.length === 2;
    }),
    probe: ({ headerId }) => {
      probes++;
      return probe({ headerId });
    },
  });
  await assert.rejects(bootstrap(config(root), result), (error) => error.code === 'SSM_FAILED');
  assert.equal(probes, 0);
  assert.match(scripts[0], /mkdir "\$run"/);
  assert.match(scripts[1], /printf %s/);
  assert.match(scripts[2], /set -- '\/tmp\/xcsh-csd-00000000-0000-4000-8000-000000000001' cleanup/);
  assert.equal(scripts.filter((script) => script.includes('mkdir "$run"')).length, 1);
  const lock = JSON.parse(await readFile(join(root, 'receipts', 'active.lock'), 'utf8'));
  assert.equal(lock.worker_run_id, ownedWorker('00000000-0000-4000-8000-000000000001').runId);
  assert.equal(Object.hasOwn(lock, 'worker'), false);
  assert.equal(lock.state, 'recovery-required');
});

test('bootstrap failure probes the recorded worker without creating an ephemeral root', async () => {
  const root = await workspace();
  const scripts = [];
  let controls = 0;
  const injected = deps({
    workerProbe: null,
    cleanup: null,
    executor: simulatedSsm((script) => {
      scripts.push(script);
    }),
    readiness: async () => ({ payment_health: false }),
    probe: ({ headerId, worker }) => {
      assert.deepEqual(worker, ownedWorker('00000000-0000-4000-8000-000000000001'));
      controls++;
      return probe({ headerId });
    },
  });
  await assert.rejects(bootstrap(config(root), injected), (error) => error.code === 'READINESS_FAILED');
  assert.ok(controls >= 2);
  assert.equal(scripts.filter((script) => script.includes('mkdir "$run"')).length, 1);
  assert.equal(
    JSON.parse(await readFile(join(root, 'receipts', 'active.lock'), 'utf8')).worker_run_id,
    ownedWorker('00000000-0000-4000-8000-000000000001').runId,
  );
});

test('single-header partial preparation re-prepares only its recorded root after verified cleanup', async () => {
  const root = await workspace();
  const scripts = [];
  let probes = 0;
  const result = await runHeader(
    config(root),
    deps({
      workerProbe: null,
      cleanup: null,
      executor: simulatedSsm((script) => {
        scripts.push(script);
        return scripts.length === 2;
      }),
      probe: ({ headerId, worker }) => {
        probes++;
        assert.deepEqual(worker, ownedWorker('00000000-0000-4000-8000-000000000001'));
        return probe({ headerId });
      },
    }),
    'x-content-type-options',
  );
  assert.equal(result.outcome, 'INVALID_TEST');
  assert.equal(result.recovery.success, true);
  assert.ok(probes >= 2);
  const mkdirs = scripts
    .map((script, index) => (script.includes('mkdir "$run"') ? index : -1))
    .filter((index) => index >= 0);
  const cleanup = scripts.findIndex((script) =>
    script.includes("set -- '/tmp/xcsh-csd-00000000-0000-4000-8000-000000000001' cleanup"),
  );
  assert.equal(mkdirs.length, 2);
  assert.ok(mkdirs[0] < cleanup && cleanup < mkdirs[1]);
  assert.ok(
    scripts
      .slice(mkdirs[1])
      .some((script) => script.includes("set -- '/tmp/xcsh-csd-00000000-0000-4000-8000-000000000001' cleanup")),
  );
  await assert.rejects(stat(join(root, 'receipts', 'active.lock')), /ENOENT/);
});

test('single header records root before failed preparation and cannot issue clean receipt', async () => {
  const root = await workspace();
  const base = executor();
  let commands = 0;
  const injected = deps({
    workerProbe: null,
    executor: async (argv, options) => {
      if (argv[1] !== 'ssm') return base(argv, options);
      if (argv[2] === 'send-command') {
        const lock = JSON.parse(await readFile(join(root, 'receipts', 'active.lock'), 'utf8'));
        assert.equal(lock.worker_run_id, ownedWorker('00000000-0000-4000-8000-000000000001').runId);
        assert.equal(Object.hasOwn(lock, 'worker'), false);
        commands++;
      }
      return { code: 1, stdout: '', stderr: '' };
    },
  });
  const receipt = await runHeader(config(root), injected, 'x-content-type-options');
  assert.ok(commands >= 2, 'preparation and original-root cleanup were both attempted');
  assert.equal(receipt.outcome, 'INVALID_TEST');
  assert.equal(receipt.recovery.success, false);
  assert.equal(JSON.parse(await readFile(join(root, 'receipts', 'active.lock'), 'utf8')).state, 'recovery-required');
});

test('single header persists shared worker root rather than header run id', async () => {
  const root = await workspace();
  const shared = ownedWorker('00000000-0000-4000-8000-000000000002');
  let checked = false;
  const injected = deps({
    probe: async ({ headerId }) => {
      const lock = JSON.parse(await readFile(join(root, 'receipts', 'active.lock'), 'utf8'));
      assert.equal(lock.worker_run_id, shared.runId);
      assert.equal(Object.hasOwn(lock, 'worker'), false);
      checked = true;
      return probe({ headerId });
    },
  });
  const result = await runHeader(config(root), injected, 'x-content-type-options', {
    worker: shared,
    finalizeWorker: false,
  });
  assert.equal(result.recovery.success, true);
  assert.equal(checked, true);
});

test('interrupted recovery checks the original root before new controls and releases only after clean scan', async () => {
  const root = await workspace();
  await mkdir(join(root, 'receipts'), { recursive: true });
  const original = ownedWorker('00000000-0000-4000-8000-000000000003');
  await writeFile(
    join(root, 'receipts', 'active.lock'),
    JSON.stringify({
      run_id: 'old-case',
      command: 'run',
      started_at: START,
      state: 'recovery-required',
      worker_run_id: original.runId,
    }),
  );
  const base = executor();
  let scanned = false;
  let commandText = '';
  const injected = deps({
    executor: async (argv, options) => {
      if (argv[1] !== 'ssm') return base(argv, options);
      if (argv[2] === 'send-command') {
        commandText = JSON.parse(argv[argv.indexOf('--parameters') + 1]).commands[0];
        assert.ok(commandText.includes(`set -- '${original.root}' cleanup`));
        assert.doesNotMatch(commandText, /kill -|pgrep|secret-not-for-receipts/);
        scanned = true;
        return { code: 0, stdout: JSON.stringify({ Command: { CommandId: 'scan-1' } }), stderr: '' };
      }
      return { code: 0, stdout: JSON.stringify({ Status: 'Success', ResponseCode: 0 }), stderr: '' };
    },
    probe: ({ headerId }) => {
      assert.equal(scanned, true);
      return probe({ headerId });
    },
  });
  const result = await runHeader(config(root), injected, 'x-content-type-options');
  assert.equal(result.recovery.success, true);
  const recoveryName = (await readdir(join(root, 'receipts'))).find((name) => name.startsWith('recovery-old-case-'));
  const recoveryReceipt = JSON.parse(await readFile(join(root, 'receipts', recoveryName), 'utf8'));
  assert.deepEqual(recoveryReceipt.recovery.original_worker_cleanup, { worker_artifacts_removed: true });
  assert.equal(scanned, true);
  assert.match(commandText, /arg\.startswith\(prefix\) and arg\.endswith\(b'\/profile'\)/);
  assert.match(commandText, /re\.fullmatch/);
  await assert.rejects(stat(join(root, 'receipts', 'active.lock')), /ENOENT/);
});

test('interruption reuses recorded root and retains it if recovery preparation fails', async () => {
  for (const failPreparation of [false, true]) {
    const root = await workspace();
    await mkdir(join(root, 'receipts'), { recursive: true });
    const original = ownedWorker('00000000-0000-4000-8000-000000000003');
    await writeFile(
      join(root, 'receipts', 'active.lock'),
      JSON.stringify({
        run_id: 'old-case',
        command: 'run',
        started_at: START,
        state: 'recovery-required',
        worker_run_id: original.runId,
      }),
    );
    const scripts = [];
    let controls = 0;
    let nextId = 0;
    const injected = deps({
      workerProbe: null,
      cleanup: null,
      randomUUID: () => `00000000-0000-4000-8000-${String(++nextId).padStart(12, '0')}`,
      executor: simulatedSsm(async (script) => {
        scripts.push(script);
        if (script.includes('mkdir "$run"') && script.includes(original.root)) {
          const lock = JSON.parse(await readFile(join(root, 'receipts', 'active.lock'), 'utf8'));
          assert.equal(lock.worker_run_id, original.runId);
          assert.equal(Object.hasOwn(lock, 'worker'), false);
          return failPreparation;
        }
        return false;
      }),
      probe: ({ headerId, worker }) => {
        if (worker?.root === original.root) controls++;
        return probe({ headerId });
      },
    });
    if (failPreparation) {
      await assert.rejects(
        runHeader(config(root), injected, 'x-content-type-options'),
        (error) => error.code === 'SSM_FAILED',
      );
      const lock = JSON.parse(await readFile(join(root, 'receipts', 'active.lock'), 'utf8'));
      assert.equal(lock.worker_run_id, original.runId);
      assert.equal(Object.hasOwn(lock, 'worker'), false);
      assert.equal(lock.state, 'recovery-required');
      assert.equal(controls, 0);
    } else {
      const receipt = await runHeader(config(root), injected, 'x-content-type-options');
      assert.equal(receipt.recovery.success, true);
      assert.ok(controls >= 2);
      await assert.rejects(stat(join(root, 'receipts', 'active.lock')), /ENOENT/);
    }
    assert.ok(scripts[0].includes(`set -- '${original.root}' cleanup`));
    assert.ok(scripts[1].includes(`run='${original.root}';mkdir "$run"`));
    if (!failPreparation) {
      const lastOldCleanup = scripts.findIndex(
        (script, index) => index > 1 && script.includes(`set -- '${original.root}' cleanup`),
      );
      const nextRoot = scripts.findIndex(
        (script) => script.includes('mkdir "$run"') && !script.includes(original.root),
      );
      assert.ok(lastOldCleanup > 1 && nextRoot > lastOldCleanup);
    }
  }
});

test('legacy or invalid worker run references fail closed without SSM or control probes', async () => {
  for (const workerRunId of [undefined, '../../unsafe']) {
    const root = await workspace();
    await mkdir(join(root, 'receipts'), { recursive: true });
    const record = { run_id: 'old-case', command: 'run', started_at: START, state: 'recovery-required' };
    if (workerRunId !== undefined) record.worker_run_id = workerRunId;
    await writeFile(join(root, 'receipts', 'active.lock'), JSON.stringify(record));
    let touched = false;
    await assert.rejects(
      runHeader(
        config(root),
        deps({
          executor: async (argv, options) => {
            if (argv[1] === 'ssm') {
              touched = true;
              throw new Error('unsafe SSM');
            }
            return executor()(argv, options);
          },
          probe: () => {
            touched = true;
            throw new Error('unsafe probe');
          },
        }),
        'x-content-type-options',
      ),
      (error) => error.code === 'WORKER_IDENTITY_INVALID',
    );
    assert.equal(touched, false);
    const lock = JSON.parse(await readFile(join(root, 'receipts', 'active.lock'), 'utf8'));
    assert.equal(lock.state, 'recovery-required');
    assert.equal(Object.hasOwn(lock, 'worker'), false);
  }
});

test('interrupted recovery stops on original-root live profile without fresh probes', async () => {
  const root = await workspace();
  await mkdir(join(root, 'receipts'), { recursive: true });
  const original = ownedWorker('00000000-0000-4000-8000-000000000003');
  await writeFile(
    join(root, 'receipts', 'active.lock'),
    JSON.stringify({
      run_id: 'old-case',
      command: 'run',
      started_at: START,
      state: 'recovery-required',
      worker_run_id: original.runId,
    }),
  );
  let probes = 0;
  let cleanupCommands = 0;
  const base = executor();
  await assert.rejects(
    runHeader(
      config(root),
      deps({
        probe: () => {
          probes++;
          return probe();
        },
        executor: async (argv, options) => {
          if (argv[1] !== 'ssm') return base(argv, options);
          if (argv[2] === 'send-command') {
            cleanupCommands++;
            const script = JSON.parse(argv[argv.indexOf('--parameters') + 1]).commands[0];
            assert.ok(script.includes(`set -- '${original.root}' cleanup`));
            return { code: 0, stdout: JSON.stringify({ Command: { CommandId: 'still-running' } }), stderr: '' };
          }
          return { code: 0, stdout: JSON.stringify({ Status: 'Failed', ResponseCode: 42 }), stderr: '' };
        },
      }),
      'x-content-type-options',
    ),
    (error) => error.code === 'RECOVERY_FAILED',
  );
  assert.equal(cleanupCommands, 1);
  assert.equal(probes, 0);
  const lock = JSON.parse(await readFile(join(root, 'receipts', 'active.lock'), 'utf8'));
  assert.equal(lock.state, 'recovery-required');
  assert.equal(lock.worker_run_id, original.runId);
  assert.equal(Object.hasOwn(lock, 'worker'), false);
  assert.equal(lock.recovery_completed, false);
});

test('worker cleanup refuses a live profile or uncertain SSM and never signals a process', async () => {
  const root = await workspace();
  const workerConfig = config(root);
  await validateDeploymentIdentity(workerConfig, deps());
  const base = executor();
  let sends = 0;
  for (const responseCode of [1, 0]) {
    let script = '';
    const injected = deps({
      executor: async (argv, options) => {
        if (argv[1] !== 'ssm') return base(argv, options);
        if (argv[2] === 'send-command') {
          sends++;
          const serialized = argv[argv.indexOf('--parameters') + 1];
          assert.ok(serialized.length <= 4096);
          script = JSON.parse(serialized).commands[0];
          assert.ok(script.length <= 4096);
          assert.doesNotMatch(script, /pgrep|kill\s+-|os\.kill|secret-not-for-receipts/);
          assert.match(script, /scan\(\)[\s\S]*shutil\.rmtree\(root\)[\s\S]*scan\(\)/);
          return { code: 0, stdout: JSON.stringify({ Command: { CommandId: 'scan-1' } }), stderr: '' };
        }
        return {
          code: 0,
          stdout: JSON.stringify({ Status: responseCode ? 'Failed' : 'Success', ResponseCode: responseCode }),
          stderr: '',
        };
      },
    });
    assert.deepEqual(await cleanupWorker(workerConfig, injected, ownedWorker()), {
      worker_artifacts_removed: responseCode === 0,
    });
  }
  const before = sends;
  assert.deepEqual(await cleanupWorker(workerConfig, deps(), { ...ownedWorker(), root: '/tmp/xcsh-csd-other' }), {
    worker_artifacts_removed: false,
  });
  assert.equal(sends, before);
});

test('self-owned worker probe rejects successful browser result when root cleanup fails', async () => {
  const root = await workspace();
  const workerConfig = config(root);
  await validateDeploymentIdentity(workerConfig, deps());
  const scripts = [];
  await assert.rejects(
    runWorkerProbe(
      workerConfig,
      deps({
        executor: simulatedSsm((script) => {
          scripts.push(script);
          return script.includes('shutil.rmtree(root)');
        }),
      }),
      'x-frame-options',
    ),
    (error) => error.code === 'RECOVERY_FAILED' && /cleanup failed/.test(error.message),
  );
  assert.ok(scripts.some((script) => script.includes('sudo -u ubuntu -H')));
  assert.ok(scripts.some((script) => script.includes('shutil.rmtree(root)')));
  assert.ok(scripts.every((script) => !/pgrep|kill\s+-|os\.kill/.test(script)));
});

test('production worker keeps every current-source SSM command and parameters value within 4096 characters', async () => {
  const root = await workspace();
  const workerConfig = config(root);
  await validateDeploymentIdentity(workerConfig, deps());
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
  assert.deepEqual(await runWorkerProbe(workerConfig, injected, 'x-frame-options'), result);
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
  assert.ok(commands.some((value) => value.includes('shutil.rmtree(root)')));
  assert.ok(commands.some((value) => value.includes('cmd.read(65537)')));
  assert.ok(commands.every((value) => !value.includes('pgrep -f')));
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

test('stale recovery claims are reclaimed by age without persisting host or PID', async () => {
  const root = await workspace();
  const receiptDir = join(root, 'receipts');
  const claimDir = join(receiptDir, 'recovery.claim');
  await mkdir(claimDir, { recursive: true });
  await writeFile(
    join(claimDir, 'owner.json'),
    JSON.stringify({ claim_id: 'stale-claim', run_id: 'original-run', claimed_at: START }),
  );
  await utimes(claimDir, new Date(0), new Date(0));
  await writeFile(
    join(receiptDir, 'active.lock'),
    JSON.stringify({
      run_id: 'original-run',
      command: 'run',
      started_at: START,
      state: 'recovery-required',
      worker_run_id: null,
    }),
  );
  const result = await runHeader(
    config(root, { timings: { ...config(root).timings, maximumCaseMs: 60 * 60_000 } }),
    deps(),
    'x-content-type-options',
  );
  assert.equal(result.recovery.success, true);
  await assert.rejects(stat(claimDir), /ENOENT/);
});

test('fresh recovery claims remain age-gated without host or PID metadata', async () => {
  for (const claimId of ['live-claim', 'foreign-claim', 'legacy-claim']) {
    const root = await workspace();
    const receiptDir = join(root, 'receipts');
    const claimDir = join(receiptDir, 'recovery.claim');
    await mkdir(claimDir, { recursive: true });
    await writeFile(
      join(claimDir, 'owner.json'),
      JSON.stringify({ claim_id: claimId, run_id: 'original-run', claimed_at: START }),
    );
    await writeFile(
      join(receiptDir, 'active.lock'),
      JSON.stringify({
        run_id: 'original-run',
        command: 'run',
        started_at: START,
        state: 'recovery-required',
        worker_run_id: null,
      }),
    );
    await assert.rejects(
      runHeader(
        config(root, { timings: { ...config(root).timings, maximumCaseMs: 60 * 60_000 } }),
        deps(),
        'x-content-type-options',
      ),
      (error) => error.code === 'OVERLAP',
    );
  }
});

test('headed worker single canary is explicit and defaults remain unchanged', async () => {
  const { parseArgs } = await import('../scripts/csd-page-tamper.mjs');
  const env = {
    AWS_PROFILE: '280469140135_Users',
    AWS_REGION: 'us-east-1',
    XCSH_CSD_AWS_ACCOUNT: '280469140135',
    XCSH_CSD_TERRAFORM_DIR: '/fixture/csd',
    XCSH_CSD_TRAFFIC_GENERATOR_TERRAFORM_DIR: '/fixture/tgen',
    XCSH_API_URL: 'https://f5-sales-demo.console.ves.volterra.io',
    XCSH_API_TOKEN: 'fixture',
    XCSH_NAMESPACE: 'client-side-defense',
    XCSH_LB_NAME: 'client-side-defense',
    XCSH_CSD_PAGE_TAMPER_RECEIPT_DIR: '/fixture/receipts',
  };
  const result = parseArgs(['canary', '--browser-mode', 'headed-xvfb', '--placement', 'worker'], env);
  assert.equal(result.config.browserMode, 'headed-xvfb');
  assert.equal(result.config.placement, 'worker');
  assert.equal(parseArgs(['run', '--header', 'x-content-type-options'], env).config.browserMode, 'headless');
  assert.throws(
    () => parseArgs(['canary', '--browser-mode', 'headed-xvfb', '--placement', 'workstation'], env),
    /worker/,
  );
  assert.throws(() => parseArgs(['suite', '--browser-mode', 'headed-xvfb', '--placement', 'worker'], env), /canary/);
});

test('worker placement keeps every control and selector visit remote and fails closed on missing provenance', async () => {
  const root = await workspace();
  const locations = [];
  const evidence = {
    mode: 'headed-xvfb',
    placement: 'worker',
    process_arguments_verified: true,
    browser_arguments_verified: true,
    owned_display_verified: true,
  };
  const result = await runHeader(
    config(root, { browserMode: 'headed-xvfb', placement: 'worker' }),
    deps({
      probe: ({ headerId, location }) => {
        locations.push(location);
        return { ...probe({ headerId }), browser_provenance: evidence };
      },
    }),
    'x-content-type-options',
  );
  assert.equal(result.outcome, 'COMPROMISED');
  assert.ok(locations.length > 2);
  assert.ok(locations.every((location) => location === 'worker'));
  const invalid = await runHeader(
    config(await workspace(), { browserMode: 'headed-xvfb', placement: 'worker' }),
    deps(),
    'x-content-type-options',
  );
  assert.equal(invalid.outcome, 'INVALID_TEST');
});

test('persistent Linux reservation restores fixture states after normal, abort, hard kill and boot-trigger execution', {
  skip: process.env.XCSH_CSD_LINUX_FIXTURES !== '1',
  timeout: 180_000,
}, async () => {
  const { randomUUID } = await import('node:crypto');
  const { renderReservation, reservationLifetime } = await import('../scripts/lib/csd-page-tamper-reservation.mjs');
  assert.ok(reservationLifetime(DEFAULT_TIMINGS) > 3 * 60 * 60);
  for (const scenario of ['normal', 'abort', 'kill', 'boot'])
    for (const active of [false, true]) {
      const enabled = scenario === 'kill' || scenario === 'boot';
      const runId = randomUUID();
      const name = `xcsh-csd-fixture-${runId}`;
      const service = `${name}.service`;
      const timer = `${name}.timer`;
      const guard = renderReservation({
        runId,
        lifetimeSeconds: scenario === 'boot' ? 60 : 6,
        service,
        timer,
        fixture: true,
      });
      const root = await mkdtemp(join(tmpdir(), 'csd-guard-fixture-'));
      const script = join(root, 'guard.py');
      await writeFile(script, guard.script);
      const ctl = (...args) => {
        const r = spawnSync('sudo', ['-n', 'systemctl', ...args], { encoding: 'utf8' });
        assert.equal(r.status, 0, r.stderr);
        return r.stdout.trim();
      };
      const run = (action) => {
        const r = spawnSync('sudo', ['-n', 'python3', script, action], { encoding: 'utf8' });
        assert.equal(r.status, 0, r.stderr);
        return r.stdout;
      };
      await writeFile(
        join(root, service),
        '[Unit]\nDescription=Isolated CSD fixture\n[Service]\nType=simple\nExecStart=/usr/bin/sleep infinity\n[Install]\nWantedBy=multi-user.target\n',
      );
      await writeFile(
        join(root, timer),
        `[Timer]\nOnActiveSec=1h\nUnit=${service}\n[Install]\nWantedBy=timers.target\n`,
      );
      const install = spawnSync(
        'sudo',
        ['-n', 'install', '-m', '644', join(root, service), join(root, timer), '/etc/systemd/system/'],
        { encoding: 'utf8' },
      );
      assert.equal(install.status, 0, install.stderr);
      ctl('daemon-reload');
      try {
        if (enabled) {
          ctl('enable', timer);
          ctl('enable', service);
        }
        if (active) {
          ctl('start', service);
          ctl('start', timer);
        }
        assert.match(run('arm'), /"armed": true/);
        assert.equal(ctl('show', timer, '-p', 'ActiveState', '--value'), 'inactive');
        assert.equal(ctl('show', service, '-p', 'ActiveState', '--value'), 'inactive');
        if (scenario === 'kill') {
          const controller = spawnSync('sh', ['-c', 'kill -KILL $$']);
          assert.equal(controller.signal, 'SIGKILL');
          await new Promise((resolve) => setTimeout(resolve, 8000));
        } else if (scenario === 'boot') {
          // Exercise installed boot configuration on the running fixture host, not a host reboot.
          const r = spawnSync('sudo', ['-n', 'rm', '-f', `/run/systemd/system/${guard.name}.timer.d/boot.conf`]);
          assert.equal(r.status, 0);
          ctl('daemon-reload');
          ctl('restart', `${guard.name}.timer`);
          await new Promise((resolve) => setTimeout(resolve, 3000));
        } else {
          if (scenario === 'abort') assert.equal(spawnSync('sh', ['-c', 'kill -TERM $$']).signal, 'SIGTERM');
          run('restore');
        }
        assert.equal(ctl('show', timer, '-p', 'UnitFileState', '--value'), enabled ? 'enabled' : 'disabled');
        assert.equal(ctl('show', timer, '-p', 'ActiveState', '--value'), active ? 'active' : 'inactive');
        assert.equal(ctl('show', service, '-p', 'ActiveState', '--value'), active ? 'active' : 'inactive');
        assert.equal(ctl('show', service, '-p', 'UnitFileState', '--value'), enabled ? 'enabled' : 'disabled');
        run('cleanup');
      } finally {
        ctl('disable', '--now', timer);
        ctl('disable', '--now', service);
        const cleanup = spawnSync('sudo', [
          '-n',
          'rm',
          '-f',
          `/etc/systemd/system/${timer}`,
          `/etc/systemd/system/${service}`,
        ]);
        assert.equal(cleanup.status, 0);
        ctl('daemon-reload');
      }
    }
});

test('Linux owned Xvfb Chrome fixture verifies real headed provenance and cleanup', {
  skip: process.env.XCSH_CSD_LINUX_FIXTURES !== '1',
  timeout: 60_000,
}, async () => {
  const { randomUUID } = await import('node:crypto');
  const { renderHeadedProbe } = await import('../scripts/lib/csd-page-tamper-reservation.mjs');
  const runId = randomUUID();
  const root = `/tmp/xcsh-csd-${runId}`;
  await mkdir(root, { mode: 0o700 });
  const script = join(root, 'fixture.py');
  // No production endpoint: local data fixture with the same CDP client as runDocumentProbe.
  const client = new URL('../scripts/lib/csd-runner.mjs', import.meta.url).pathname;
  const entry = `import { CdpClient } from '${client}';
const v=await(await fetch('http://127.0.0.1:'+process.env.XCSH_PROBE_PORT+'/json/version')).json();
const c=await CdpClient.connect(v.webSocketDebuggerUrl,10000,WebSocket);try{
const args=await c.send('Browser.getBrowserCommandLine');const version=await c.send('Browser.getVersion');
const target=await c.send('Target.createTarget',{url:'data:text/html,<title>isolated-fixture</title>'});
await c.send('Target.closeTarget',{targetId:target.targetId});
console.log('XCSH_RESULT '+JSON.stringify({success:true,_browser_evidence:{arguments:args.arguments,product:version.product}}));}finally{c.close();}`;
  await writeFile(script, renderHeadedProbe({ root, entry }));
  const r = spawnSync('python3', [script], { encoding: 'utf8', timeout: 45000 });
  assert.equal(r.status, 0, r.stderr);
  const result = JSON.parse(r.stdout.trim().slice(12));
  assert.equal(result.browser_provenance.mode, 'headed-xvfb');
  assert.equal(result.browser_provenance.owned_display_verified, true);
  assert.deepEqual(
    (await readdir(root)).filter((file) => file.startsWith('probe-')),
    [],
  );
});

test('single headed canary arms once across baseline and case and keeps alert outcomes separate', async () => {
  const { runCanary } = await import('../scripts/lib/csd-page-tamper-controller.mjs');
  for (const [name, outcome] of [
    ['ClientSideDefenseHttpHeaderModified', 'MODIFIED_ONLY'],
    ['ClientSideDefenseHttpHeaderCompromised', 'COMPROMISED'],
  ]) {
    const root = await workspace();
    const actions = [];
    const visits = [];
    const c = config(root, { browserMode: 'headed-xvfb', placement: 'worker' });
    const result = await runCanary(
      c,
      deps({
        reservation: async (action) => {
          actions.push(action);
          return { armed: true, dispatch_drained: true, restored: true, original_states_preserved: true };
        },
        probe: ({ headerId, location }) => {
          visits.push(location);
          return {
            ...probe({ headerId }),
            browser_provenance: {
              mode: 'headed-xvfb',
              placement: 'worker',
              process_arguments_verified: true,
              browser_arguments_verified: true,
              owned_display_verified: true,
            },
          };
        },
        alertSource: async () => [[alert(name)]],
      }),
    );
    assert.equal(result.outcome, outcome);
    assert.deepEqual(actions, ['arm', 'restore', 'cleanup']);
    assert.ok(visits.every((location) => location === 'worker'));
    assert.equal(result.reservation.restored, true);
    assert.equal(result.browser_provenance.mode, 'headed-xvfb');
    assert.equal((await status(c)).active, false);
  }
});
