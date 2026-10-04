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
      return {
        code: 0,
        stdout: JSON.stringify({ Account: '280469140135' }),
        stderr: '',
      };
    if (argv[0] === 'aws' && argv[1] === 'ec2')
      return {
        code: 0,
        stdout: JSON.stringify({
          Reservations: [
            {
              Instances: [{ InstanceId: workerInstance, State: { Name: 'running' } }],
            },
          ],
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
    cleanup: async () => ({
      worker_artifacts_removed: true,
      browser_artifacts_removed: true,
    }),
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
  const decoy = alert('UnrelatedAlert', {
    description: JSON.stringify(alert()),
  });
  assert.deepEqual(correlateAlertViews({ current: [decoy], history: [] }, expected), []);
  assert.deepEqual(correlateAlertViews({ current: [], history: [JSON.stringify(decoy)] }, expected), []);
  const history = JSON.stringify({
    '@timestamp': START,
    alerts: [JSON.stringify(alert())],
  });
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
    alert(undefined, {
      labels: {
        ...alert().labels,
        path: 'https://client-side-defense.f5-sales-demo.com/other',
      },
    }),
    alert(undefined, {
      labels: {
        ...alert().labels,
        path: 'https://other.example/csd-page-tamper/payment',
      },
    }),
    alert(undefined, {
      labels: {
        ...alert().labels,
        path: 'http://client-side-defense.f5-sales-demo.com/csd-page-tamper/payment',
      },
    }),
    alert(undefined, {
      labels: { ...alert().labels, path: '/csd-page-tamper/payment' },
    }),
    alert(undefined, { labels: { ...alert().labels, path: 'not a URL' } }),
    alert(undefined, {
      labels: { ...alert().labels, header: 'x-frame-options' },
    }),
    alert(undefined, { labels: { ...alert().labels, namespace: 'other' } }),
    alert(undefined, { startsAt: '2026-09-25T11:58:59.999Z' }),
    alert(undefined, { startsAt: '2026-09-25T12:01:00.001Z' }),
  ];
  assert.equal(correlateAlerts([invalid], expected).length, 0);
  assert.equal(
    correlateAlerts(
      [
        [
          alert(undefined, {
            labels: { ...alert().labels, header: 'X-CONTENT-TYPE-OPTIONS' },
          }),
        ],
      ],
      expected,
    ).length,
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
    labels: {
      ...alert().labels,
      header: 'x-content-type-options, x-frame-options, cache-control',
    },
    startsAt: '2026-09-25T11:58:00.123456789Z',
    status: 'firing',
    endsAt: '0001-01-01T00:00:00Z',
  });
  const resolved = {
    ...firing,
    status: 'resolved',
    endsAt: '2026-09-25T12:00:30.000Z',
  };
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
  const old = alert(undefined, {
    startsAt: '2026-09-25T11:59:59.999Z',
    endsAt: '0001-01-01T00:00:00Z',
  });
  const resolved = {
    ...old,
    status: 'resolved',
    endsAt: '2026-09-25T11:59:59.999Z',
  };
  for (const current of [[old], []]) {
    const root = await workspace();
    const result = await runHeader(
      config(root, {
        timings: { ...config(root).timings, mixedMs: 2, pollMs: 1 },
      }),
      deps({
        alertSource: async () => ({
          current: [
            ...current,
            alert(undefined, {
              labels: {
                ...alert().labels,
                path: 'https://other.example/csd-page-tamper/payment',
              },
              startsAt: old.startsAt,
            }),
            alert(undefined, {
              labels: { ...alert().labels, header: 'x-frame-options' },
              startsAt: old.startsAt,
            }),
            alert(undefined, {
              labels: {
                ...alert().labels,
                path: 'https://client-side-defense.f5-sales-demo.com/other',
              },
              startsAt: old.startsAt,
            }),
            alert(undefined, {
              labels: { ...alert().labels, namespace: 'other' },
              startsAt: old.startsAt,
            }),
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
    config(root, {
      timings: { ...config(root).timings, mixedMs: 2, pollMs: 1 },
    }),
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
    config(root, {
      timings: { ...config(root).timings, mixedMs: 2, pollMs: 1 },
    }),
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
    config(root, {
      timings: { ...config(root).timings, minimumPairs: 2, maximumCaseMs: 1 },
    }),
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
      cleanup: async () => ({
        worker_artifacts_removed: false,
        browser_artifacts_removed: true,
      }),
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
    JSON.stringify({
      claim_id: 'stale-owner',
      run_id: 'original-run',
      original_command: 'run',
      original_started_at: START,
      claimed_at: START,
    }),
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
  const resolvedAlert = {
    ...currentAlert,
    status: 'resolved',
    endsAt: '2026-09-25T12:00:30.000Z',
  };
  const result = await bootstrap(
    config(root, {
      timings: {
        ...config(root).timings,
        bootstrapControlMs: 2,
        quietMs: 0,
        pollMs: 1,
      },
    }),
    deps({
      alertSource: null,
      fetch: async (url) => ({
        ok: true,
        json: async () =>
          new URL(url).pathname.endsWith('/history')
            ? {
                alerts: [JSON.stringify(resolvedAlert)],
                total_hits: '1',
                scroll_id: '',
              }
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
    config(root, {
      timings: {
        ...config(root).timings,
        bootstrapControlMs: 2,
        quietMs: 0,
        pollMs: 1,
      },
    }),
    deps({
      alertSource: null,
      fetch: async (url) => {
        urls.push(url);
        return {
          ok: true,
          json: async () =>
            new URL(url).pathname.endsWith('/history')
              ? {
                  alerts: [],
                  total_hits: '0',
                  scroll_id: 'stable-zero-hit-cursor',
                }
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
    config(root, {
      timings: {
        ...config(root).timings,
        bootstrapControlMs: 1,
        quietMs: 0,
        pollMs: 1,
      },
    }),
    deps({
      alertSource: null,
      fetch: async (url, options) => {
        urls.push(url);
        assert.equal(options.headers.Authorization, 'APIToken secret-not-for-receipts');
        const path = new URL(url).pathname;
        const body = path.endsWith('/history/scroll')
          ? { alerts: [record], total_hits: '501', scroll_id: 'still-present' }
          : path.endsWith('/history')
            ? {
                alerts: Array(500).fill(record),
                total_hits: '501',
                scroll_id: 'next-page',
              }
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
        config(root, {
          timings: {
            ...config(root).timings,
            bootstrapControlMs: 1,
            quietMs: 0,
            pollMs: 1,
          },
        }),
        deps({
          alertSource: null,
          fetch: async (url) => {
            const path = new URL(url).pathname;
            if (path.endsWith('/history/scroll')) scrollCalls += 1;
            if (failure === 'http-error' && path.endsWith('/history')) return { ok: false };
            const body = path.endsWith('/history/scroll')
              ? {
                  alerts: [JSON.stringify(alert())],
                  total_hits: '3',
                  scroll_id: 'same',
                }
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
        return {
          worker_artifacts_removed: cleanupCalls <= HEADER_IDS.length,
          browser_artifacts_removed: true,
        };
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
        return {
          worker_artifacts_removed: true,
          browser_artifacts_removed: true,
        };
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
      timings: {
        ...config(root).timings,
        bootstrapControlMs: 3,
        quietMs: 0,
        pollMs: 1,
      },
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
    config(root, {
      timings: {
        ...config(root).timings,
        bootstrapControlMs: 1,
        quietMs: 3,
        pollMs: 1,
      },
    }),
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
    config(root, {
      timings: {
        ...config(root).timings,
        bootstrapControlMs: 0,
        quietMs: 3,
        pollMs: 1,
      },
    }),
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
  const resolved = {
    ...oldFiring,
    status: 'resolved',
    endsAt: new Date(now + 2).toISOString(),
  };
  const result = await bootstrap(
    config(root, {
      timings: {
        ...config(root).timings,
        bootstrapControlMs: 0,
        quietMs: 3,
        pollMs: 1,
      },
    }),
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
    executor: simulatedSsm((script) => {
      if (script.startsWith('set -- ') && script.includes('worker_quarantine(')) {
        cleanupCommands++;
        return true;
      }
    }),
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
    config(root, {
      timings: { ...config(root).timings, recoveryMs: 3, pollMs: 1 },
    }),
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

function fixtureTransport() {
  const staging = new Map();
  const installed = new Map();
  return (script) => {
    const stage = script.match(/python3 - '(\/var\/lib\/xcsh-csd-install-[^']+)'/);
    if (stage && script.includes("os.write(f,b'")) {
      staging.set(stage[1], (staging.get(stage[1]) || '') + script.match(/os.write\(f,b'([^']*)'\)/)[1]);
      return null;
    }
    if (script.includes('body=base64.b64decode(source.read(),validate=True)')) {
      const source = script.match(/os.open\('([^']+)\/payload'/)[1];
      const directory = script.match(/python3 - '([^']+)'/)[1];
      const name = script.match(/os.rename\(name,'([^']+)'/)[1];
      installed.set(`${directory}/${name}`, Buffer.from(staging.get(source) || '', 'base64').toString());
      return null;
    }
    if (script.includes('os.mkdir(') && /xcsh-csd-(?:install|command)-/.test(script)) return null;
    if (script.includes("os.unlink('payload'") || script.includes("os.unlink('command.sh'")) return null;
    const invocation = script.match(/^\/bin\/sh '([^']+)'$/);
    if (invocation) return installed.get(invocation[1]);
    return script;
  };
}

function simulatedSsm(onScript, result = probe()) {
  const base = executor();
  let commandId = 0;
  let pendingFailure = false;
  const decode = fixtureTransport();
  let effective = '';
  const identities = new Map();
  return async (argv, options) => {
    if (argv[1] !== 'ssm') return base(argv, options);
    if (argv[2] === 'send-command') {
      const script = JSON.parse(argv[argv.indexOf('--parameters') + 1]).commands[0];
      effective = decode(script) || '';
      const identity = effective.match(/identity=(\{[^\n]+\});mode=/);
      if (identity) identities.set(JSON.parse(identity[1]).runId, JSON.parse(identity[1]));
      pendingFailure = effective ? (await onScript(effective)) === true : false;
      return {
        code: 0,
        stdout: JSON.stringify({
          Command: { CommandId: `cmd-${++commandId}` },
        }),
        stderr: '',
      };
    }
    if (argv[2] === 'get-command-invocation')
      return {
        code: 0,
        stdout: JSON.stringify({
          Status: pendingFailure ? 'Failed' : 'Success',
          ResponseCode: pendingFailure ? 42 : 0,
          StandardOutputContent: `XCSH_RESULT ${JSON.stringify(effective.match(/helper.py' 'initialize'$/) ? { schema_version: 1, externally_verified: true, worker_identity: identities.get(effective.match(/recovery\/([^/]+)\/helper.py/)[1]), prearm: true, restoration: { restored: false, required: false }, worker_artifacts_removed: false, reservation_artifacts_removed: false } : result)}\n`,
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
  assert.match(scripts[0], /canonical_directory/);
  assert.ok(
    scripts.some((script) => script.includes("set -- '/tmp/xcsh-csd-00000000-0000-4000-8000-000000000001' cleanup")),
  );
  assert.equal(scripts.filter((script) => /helper.py' prepare$/.test(script)).length, 0);
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
  assert.equal(scripts.filter((script) => /helper.py' prepare$/.test(script)).length, 1);
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
        return /helper.py' prepare$/.test(script) && scripts.filter((s) => /helper.py' prepare$/.test(s)).length === 1;
      }),
      probe: ({ headerId, worker }) => {
        probes++;
        assert.notEqual(worker.runId, ownedWorker('00000000-0000-4000-8000-000000000001').runId);
        return probe({ headerId });
      },
    }),
    'x-content-type-options',
  );
  assert.equal(result.outcome, 'INVALID_TEST');
  assert.equal(result.recovery.success, true);
  assert.ok(probes >= 2);
  const mkdirs = scripts
    .map((script, index) => (/helper.py' prepare$/.test(script) ? index : -1))
    .filter((index) => index >= 0);
  const cleanup = scripts.findIndex((script) =>
    script.includes("set -- '/tmp/xcsh-csd-00000000-0000-4000-8000-000000000001' cleanup"),
  );
  assert.equal(mkdirs.length, 2);
  assert.ok(mkdirs[0] < cleanup && cleanup < mkdirs[1]);
  assert.ok(
    scripts
      .slice(mkdirs[1])
      .some(
        (script) =>
          /set -- '\/tmp\/xcsh-csd-/.test(script) &&
          !script.includes('/tmp/xcsh-csd-00000000-0000-4000-8000-000000000001'),
      ),
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
    executor: simulatedSsm((script) => {
      if (script.includes(`set -- '${original.root}' cleanup`)) {
        commandText = script;
        assert.doesNotMatch(script, /kill -|pgrep|secret-not-for-receipts/);
        scanned = true;
      }
    }),
    probe: ({ headerId }) => {
      assert.equal(scanned, true);
      return probe({ headerId });
    },
  });
  const result = await runHeader(config(root), injected, 'x-content-type-options');
  assert.equal(result.recovery.success, true);
  const recoveryName = (await readdir(join(root, 'receipts'))).find((name) => name.startsWith('recovery-old-case-'));
  const recoveryReceipt = JSON.parse(await readFile(join(root, 'receipts', recoveryName), 'utf8'));
  assert.deepEqual(recoveryReceipt.recovery.original_worker_cleanup, {
    worker_artifacts_removed: true,
  });
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
        if (/helper.py' prepare$/.test(script) && scripts.filter((s) => /helper.py' prepare$/.test(s)).length === 1) {
          const lock = JSON.parse(await readFile(join(root, 'receipts', 'active.lock'), 'utf8'));
          assert.equal(lock.worker_run_id, original.runId);
          assert.equal(Object.hasOwn(lock, 'worker'), false);
          assert.notEqual(lock.recovery_worker_identity.runId, original.runId);
          return failPreparation;
        }
        return false;
      }),
      probe: ({ headerId, worker }) => {
        if (worker?.root !== original.root) controls++;
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
    const prepared = scripts.findIndex((script) => /helper.py' prepare$/.test(script));
    assert.ok(prepared > 0);
    assert.ok(scripts[prepared].includes('/var/lib/xcsh-csd-recovery/'));
    assert.ok(!scripts[prepared].includes(original.runId));
  }
});

test('legacy or invalid worker run references fail closed without SSM or control probes', async () => {
  for (const workerRunId of [undefined, '../../unsafe']) {
    const root = await workspace();
    await mkdir(join(root, 'receipts'), { recursive: true });
    const record = {
      run_id: 'old-case',
      command: 'run',
      started_at: START,
      state: 'recovery-required',
    };
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
        executor: simulatedSsm((script) => {
          if (script.includes(`set -- '${original.root}' cleanup`)) {
            cleanupCommands++;
            return true;
          }
        }),
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
      executor: simulatedSsm((value) => {
        if (!value.includes('set -- ')) return false;
        sends++;
        script = value;
        assert.doesNotMatch(script, /pgrep|kill\s+-|os\.kill|secret-not-for-receipts/);
        assert.match(script, /scan\(\)[\s\S]*worker_quarantine\([\s\S]*scan\(\)/);
        return responseCode !== 0;
      }),
    });
    assert.deepEqual(await cleanupWorker(workerConfig, injected, ownedWorker()), {
      worker_artifacts_removed: responseCode === 0,
    });
  }
  const before = sends;
  assert.deepEqual(
    await cleanupWorker(workerConfig, deps(), {
      ...ownedWorker(),
      root: '/tmp/xcsh-csd-other',
    }),
    {
      worker_artifacts_removed: false,
    },
  );
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
          return script.startsWith('set -- ') && script.includes('worker_quarantine(');
        }),
      }),
      'x-frame-options',
    ),
    (error) => error.code === 'RECOVERY_FAILED' && /cleanup failed/.test(error.message),
  );
  assert.ok(scripts.some((script) => script.includes('sudo -u ubuntu -H')));
  assert.ok(scripts.some((script) => script.includes('worker_quarantine(')));
  assert.ok(
    scripts.filter((script) => script.startsWith('set -- ')).every((script) => !/pgrep|kill\s+-|os\.kill/.test(script)),
  );
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
          stdout: JSON.stringify({
            Command: { CommandId: `cmd-${++commandId}` },
          }),
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
  const decode = fixtureTransport();
  const effective = commands.map(decode).filter(Boolean);
  const maxCommand = Math.max(...commands.map((value) => value.length));
  const maxParameters = Math.max(...parameters.map((value) => value.length));
  assert.ok(sendCalls.length >= 5, 'expected init, chunks, extraction, probe, and cleanup commands');
  assert.ok(effective.some((value) => value.includes('hashlib.sha256')));
  assert.ok(commands.some((value) => value.includes('base64.b64decode')));
  assert.ok(effective.some((value) => value.includes('sudo -u ubuntu -H')));
  assert.ok(effective.some((value) => value.includes('worker_quarantine(')));
  assert.ok(effective.some((value) => value.includes('cmd.read(65537)')));
  assert.ok(commands.every((value) => !value.includes('pgrep -f')));
  const launcherStage = commands
    .find((value) => value.includes("os.rename(name,'.launch-"))
    .match(/os.open\('([^']+)\/payload'/)[1];
  const encodedWorkerScript = commands
    .filter((value) => value.includes(`python3 - '${launcherStage}'`) && value.includes("os.write(f,b'"))
    .map((value) => value.match(/os.write\(f,b'([^']+)'\)/)[1])
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
  assert.match(workerScript, /for child in "\$probe"/);
  assert.doesNotMatch(workerScript, /rm -rf "\$probe"/);
  assert.doesNotMatch(workerScript, /(?:^|;)wait(?: |;)/);
  assert.doesNotMatch(serialized, /--no-sandbox/);
  process.stdout.write(`MAX_SSM_COMMAND=${maxCommand} MAX_SSM_PARAMETERS=${maxParameters}\n`);
});

test('alert polling accumulates Modified evidence and performs a deadline poll', async () => {
  const root = await workspace();
  let polls = 0;
  let now = Date.parse(START);
  const result = await runHeader(
    config(root, {
      timings: {
        ...config(root).timings,
        mixedMs: 2,
        maximumCaseMs: 2,
        pollMs: 1,
      },
    }),
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
    config(root, {
      timings: {
        ...config(root).timings,
        mixedMs: 2,
        maximumCaseMs: 2,
        pollMs: 1,
      },
    }),
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
    JSON.stringify({
      claim_id: 'stale-claim',
      run_id: 'original-run',
      original_command: 'run',
      original_started_at: START,
      claimed_at: START,
    }),
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
    config(root, {
      timings: { ...config(root).timings, maximumCaseMs: 60 * 60_000 },
    }),
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
      JSON.stringify({
        claim_id: claimId,
        run_id: 'original-run',
        claimed_at: START,
      }),
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
        config(root, {
          timings: { ...config(root).timings, maximumCaseMs: 60 * 60_000 },
        }),
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
    config(await workspace(), {
      browserMode: 'headed-xvfb',
      placement: 'worker',
    }),
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
        const r = spawnSync('sudo', ['-n', 'systemctl', ...args], {
          encoding: 'utf8',
        });
        assert.equal(r.status, 0, r.stderr);
        return r.stdout.trim();
      };
      const run = (action) => {
        const r = spawnSync('sudo', ['-n', 'python3', script, action], {
          encoding: 'utf8',
        });
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
        for (const unit of [`${guard.name}.timer`, `${guard.name}.service`]) {
          spawnSync('sudo', ['-n', 'systemctl', 'disable', '--now', unit]);
          spawnSync('sudo', ['-n', 'systemctl', 'stop', unit]);
        }
        const cleanup = spawnSync('sudo', [
          '-n',
          'rm',
          '-f',
          `/etc/systemd/system/${timer}`,
          `/etc/systemd/system/${service}`,
          `/etc/systemd/system/${guard.name}.timer`,
          `/etc/systemd/system/${guard.name}.service`,
          `/var/lib/xcsh-csd-reservation/${service}.owner`,
          `/var/lib/xcsh-csd-reservation/${service}.mutex`,
        ]);
        assert.equal(cleanup.status, 0);
        assert.equal(
          spawnSync('sudo', ['-n', 'rm', '-rf', guard.directory, `/run/systemd/system/${guard.name}.timer.d`]).status,
          0,
        );
        await (await import('node:fs/promises')).rm(root, {
          recursive: true,
          force: true,
        });
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
  await mkdir(root, { mode: 0o755 });
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
  const probeId = randomUUID();
  await mkdir(join(root, `probe-${probeId}`), { mode: 0o700 });
  await writeFile(script, renderHeadedProbe({ root, probeId, entry }), {
    mode: 0o755,
  });
  const isRoot = process.getuid() === 0;
  const unit = `xcsh-csd-fixture-headed-${runId}.service`;
  if (isRoot) assert.equal(spawnSync('chown', ['ubuntu:ubuntu', join(root, `probe-${probeId}`)]).status, 0);
  try {
    const r = isRoot
      ? spawnSync(
          'systemd-run',
          [
            '--quiet',
            '--wait',
            '--pipe',
            '--collect',
            `--unit=${unit}`,
            '--property=User=ubuntu',
            '--property=AppArmorProfile=chrome',
            '--property=KillMode=control-group',
            '/usr/bin/python3',
            script,
          ],
          { encoding: 'utf8', timeout: 45000 },
        )
      : spawnSync('python3', [script], { encoding: 'utf8', timeout: 45000 });
    assert.equal(r.status, 0, r.stderr);
    const result = JSON.parse(r.stdout.trim().slice(12));
    assert.equal(result.browser_provenance.mode, 'headed-xvfb');
    assert.equal(result.browser_provenance.owned_display_verified, true);
    assert.deepEqual(await readdir(join(root, `probe-${probeId}`)), []);
  } finally {
    if (isRoot) spawnSync('systemctl', ['stop', unit]);
    await (await import('node:fs/promises')).rm(root, { recursive: true, force: true });
  }
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
          return {
            armed: true,
            dispatch_drained: true,
            restored: true,
            original_states_preserved: true,
          };
        },
        reservationRecovery: async (action, worker_identity) => {
          actions.push(action);
          return {
            schema_version: 1,
            externally_verified: true,
            worker_identity,
            restoration: { restored: true, original_states_preserved: true },
            worker_artifacts_removed: action === 'cleanup',
            reservation_artifacts_removed: action === 'cleanup',
          };
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
    assert.deepEqual(actions, ['initialize', 'arm', 'classify', 'restore', 'cleanup']);
    assert.ok(visits.every((location) => location === 'worker'));
    assert.equal(result.reservation.restored, true);
    assert.equal(result.browser_provenance.mode, 'headed-xvfb');
    assert.equal((await status(c)).active, false);
  }
});

test('Linux production headed launcher executes private root-installed payload as ubuntu', {
  skip: process.env.XCSH_CSD_NONROOT_PROBE !== '1',
  timeout: 120_000,
}, async () => {
  const { randomUUID } = await import('node:crypto');
  const { prepareWorker, runHeadedWorkerProbe } = await import('../scripts/lib/csd-page-tamper-controller.mjs');
  assert.equal(process.platform, 'linux');
  const account = spawnSync('id', ['-u', 'ubuntu'], { encoding: 'utf8' });
  assert.equal(account.status, 0, account.stderr);
  assert.notEqual(account.stdout.trim(), '0');
  const runId = randomUUID();
  const root = `/tmp/xcsh-csd-${runId}`;
  const workerConfig = config(root, {
    workerInstance: 'i-0123456789abcdef0',
    browserMode: 'headed-xvfb',
    placement: 'worker',
    probeTimeoutMs: 30_000,
    probeSettleMs: 5_000,
    fixtureTarget: process.env.XCSH_CSD_FIXTURE_TARGET || null,
  });
  let invocation;
  const scripts = [];
  const injected = createDependencies({
    executor: async (argv) => {
      assert.equal(argv[0], 'aws');
      assert.equal(argv[1], 'ssm');
      if (argv[2] === 'send-command') {
        const parameters = JSON.parse(argv[argv.indexOf('--parameters') + 1]);
        assert.ok(JSON.stringify(parameters).length <= 4096);
        const script = parameters.commands[0];
        scripts.push(script);
        if (script.startsWith('systemd-run ')) {
          const payload = await stat(join(root, script.match(/headed-[0-9a-f-]+\.py/)[0]));
          assert.equal(payload.uid, 0);
          assert.equal(payload.mode & 0o777, 0o755);
        }
        const result = spawnSync('sudo', ['-n', '/bin/sh', '-c', script], {
          encoding: 'utf8',
          timeout: 90_000,
          env: { ...process.env, PATH: '/opt/node/bin:/usr/bin:/bin' },
        });
        invocation = {
          Status: result.status === 0 ? 'Success' : 'Failed',
          ResponseCode: result.status,
          StandardOutputContent: result.stdout,
          StandardErrorContent: result.stderr,
        };
        return {
          code: 0,
          stdout: JSON.stringify({ Command: { CommandId: randomUUID() } }),
        };
      }
      assert.equal(argv[2], 'get-command-invocation');
      return { code: 0, stdout: JSON.stringify(invocation) };
    },
  });
  let worker;
  try {
    worker = await prepareWorker(workerConfig, injected, runId);
    const directory = await stat(root);
    assert.equal(directory.uid, 0);
    assert.equal(directory.mode & 0o777, 0o755);
    // Same decoded-root-file defect, independently verified with the actual ubuntu interpreter.
    const denial = spawnSync(
      'sudo',
      [
        '-n',
        '/bin/sh',
        '-c',
        `umask 077; printf 'pass\\n' >'${root}/denied.py'; chmod 700 '${root}/denied.py'; sudo -u ubuntu -H /usr/bin/python3 '${root}/denied.py'`,
      ],
      { encoding: 'utf8' },
    );
    assert.equal(denial.status, 2);
    assert.match(denial.stderr, /Permission denied/);
    const result = await runHeadedWorkerProbe(workerConfig, injected, null, worker);
    assert.equal(result.success, true, JSON.stringify(result.error));
    if (workerConfig.fixtureTarget) {
      assert.equal(result.fixture_target, 'data-url');
      assert.equal(result.cleanup.target_closed, true);
    } else {
      assert.equal(result.selector, null);
      assert.equal(result.document.status, 200);
      assert.ok(result.document.headers.every((header) => header.present && header.expected_match));
      assert.equal(result.instrumentation.dip_post_observed, true);
      assert.deepEqual(result.cleanup.errors, []);
    }
    assert.equal(result.browser_provenance.mode, 'headed-xvfb');
    assert.equal(result.browser_provenance.process_arguments_verified, true);
    assert.equal(result.browser_provenance.browser_arguments_verified, true);
    assert.equal(result.browser_provenance.owned_display_verified, true);
    assert.doesNotMatch(result.browser_provenance.product, /Headless/);
    assert.equal(
      (await readdir(root)).some((name) => name.startsWith('probe-') || name.startsWith('headed-')),
      false,
    );
    assert.ok(scripts.some((script) => script.includes('lifecycle.json')));
    process.stdout.write('NONROOT_HEADED_CONTROL=passed PAYLOAD_PRIVATE=verified OWNED_CLEANUP=passed\n');
  } finally {
    assert.equal((await cleanupWorker(workerConfig, injected, worker)).worker_artifacts_removed, true);
    await assert.rejects(stat(root), { code: 'ENOENT' });
    const authorityCleanup = spawnSync(
      'sudo',
      [
        '-n',
        'python3',
        '-c',
        `import pathlib,json,shutil\nj=pathlib.Path('/var/lib/xcsh-csd-recovery/${runId}');v=json.loads((j/'lifecycle.json').read_text())\nassert v['worker_identity']['runId']=='${runId}' and v.get('cleanup_intent') is True and not pathlib.Path('${root}').exists()\nshutil.rmtree(j);pathlib.Path('/tmp/.xcsh-csd-quarantine-${runId}').rmdir()`,
      ],
      { encoding: 'utf8' },
    );
    assert.equal(authorityCleanup.status, 0, authorityCleanup.stderr);
  }
});

// Real systemd regression: production dispatch is a finite, non-retained oneshot.
test('Linux durable oneshot restoration matrix and uninterrupted retries', {
  skip: process.env.XCSH_CSD_LINUX_FIXTURES !== '1',
  timeout: 180_000,
}, async () => {
  const { randomUUID } = await import('node:crypto');
  const { rm } = await import('node:fs/promises');
  const { renderReservation } = await import('../scripts/lib/csd-page-tamper-reservation.mjs');
  const records = [];
  for (const enabled of [false, true])
    for (const active of [false, true])
      for (const serviceState of ['static', 'disabled', 'enabled']) {
        const runId = randomUUID();
        const name = `xcsh-csd-fixture-${runId}`;
        const service = `${name}.service`,
          timer = `${name}.timer`;
        const guard = renderReservation({
          runId,
          service,
          timer,
          fixture: true,
          lifetimeSeconds: 120,
        });
        const root = await mkdtemp(join(tmpdir(), 'csd-oneshot-'));
        const script = join(root, 'guard.py');
        await writeFile(script, guard.script);
        const exec = (...args) => spawnSync('sudo', ['-n', ...args], { encoding: 'utf8' });
        const ctl = (...args) => {
          const r = exec('systemctl', ...args);
          assert.equal(r.status, 0, r.stderr);
          return r.stdout.trim();
        };
        const run = (mode, success = true) => {
          const r = exec('python3', script, mode);
          if (success) assert.equal(r.status, 0, r.stderr);
          else assert.notEqual(r.status, 0, 'expected a real failure');
          return r;
        };
        const prop = (unit, field) => ctl('show', unit, '-p', field, '--value');
        await writeFile(
          join(root, service),
          `[Service]\nType=oneshot\nRemainAfterExit=no\nExecStart=/bin/sh -c 'echo "$INVOCATION_ID $$" >> ${root}/invocations; sleep 8; echo complete >> ${root}/completions'\n${serviceState === 'static' ? '' : '[Install]\nWantedBy=multi-user.target\n'}`,
        );
        await writeFile(
          join(root, timer),
          `[Timer]\nOnActiveSec=1h\nUnit=${service}\n[Install]\nWantedBy=timers.target\n`,
        );
        assert.equal(
          exec('install', '-m', '644', join(root, service), join(root, timer), '/etc/systemd/system/').status,
          0,
        );
        ctl('daemon-reload');
        try {
          if (enabled) ctl('enable', timer);
          if (serviceState === 'enabled') ctl('enable', service);
          if (active) ctl('start', timer);
          run('arm');
          // Immediate dispatch is installed only while the reservation has drained it.
          await writeFile(
            join(root, timer),
            `[Timer]\nOnActiveSec=1ms\nAccuracySec=1us\nUnit=${service}\n[Install]\nWantedBy=timers.target\n`,
          );
          assert.equal(exec('install', '-m', '644', join(root, timer), '/etc/systemd/system/').status, 0);
          ctl('daemon-reload');
          if (active && !enabled && serviceState === 'static') {
            // A real invalid timer configuration fails start, without a mocked systemctl.
            // Simulate interruption AFTER durable preparation, BEFORE timer start.
            // For this disabled/static pair arm has already applied the durable policy.
            const checkpointPath = join(root, 'checkpoint.json');
            assert.equal(exec('install', '-m', '644', `${guard.directory}/state.json`, checkpointPath).status, 0);
            const checkpoint = JSON.parse(await readFile(checkpointPath, 'utf8'));
            const intentPath = join(root, 'intent.json');
            await writeFile(intentPath, JSON.stringify({ ...checkpoint, phase: 'timer_intent' }));
            assert.equal(exec('install', '-m', '700', intentPath, `${guard.directory}/state.json`).status, 0);
            await writeFile(join(root, timer), `[Timer]\nUnit=${service}\n[Install]\nWantedBy=timers.target\n`);
            assert.equal(exec('install', '-m', '644', join(root, timer), '/etc/systemd/system/').status, 0);
            ctl('daemon-reload');
            assert.match(run('restore', false).stderr, /systemd operation failed: start/);
            await writeFile(
              join(root, timer),
              `[Timer]\nOnActiveSec=1ms\nAccuracySec=1us\nUnit=${service}\n[Install]\nWantedBy=timers.target\n`,
            );
            assert.equal(exec('install', '-m', '644', join(root, timer), '/etc/systemd/system/').status, 0);
            ctl('daemon-reload');
          }
          run('restore');
          assert.equal(prop(timer, 'UnitFileState'), enabled ? 'enabled' : 'disabled');
          assert.equal(prop(timer, 'ActiveState'), active ? 'active' : 'inactive');
          assert.equal(prop(service, 'UnitFileState'), serviceState);
          if (active) {
            for (let n = 0; n < 100 && prop(service, 'ActiveState') !== 'activating'; n++)
              await new Promise((r) => setTimeout(r, 20));
            assert.equal(prop(service, 'ActiveState'), 'activating');
            const pid = prop(service, 'MainPID'),
              invocation = prop(service, 'InvocationID');
            run('restore');
            assert.equal(prop(service, 'MainPID'), pid);
            assert.equal(prop(service, 'InvocationID'), invocation);
            if (!enabled && serviceState === 'static') {
              assert.equal(exec('stat', '-c', '%u:%a', guard.directory).stdout.trim(), '0:700');
              for (const file of ['guard.py', 'state.json'])
                assert.equal(exec('stat', '-c', '%u:%a', `${guard.directory}/${file}`).stdout.trim(), '0:700');
              const snapshotPath = join(root, 'snapshot.json');
              assert.equal(exec('install', '-m', '644', `${guard.directory}/state.json`, snapshotPath).status, 0);
              const snapshot = JSON.parse(await readFile(snapshotPath, 'utf8'));
              await rm(snapshotPath);
              // Crash after timer start but before saving resumed: observe, never restart.
              await writeFile(
                snapshotPath,
                JSON.stringify({
                  ...snapshot,
                  phase: 'timer_intent',
                  restored: false,
                }),
              );
              assert.equal(exec('install', '-m', '700', snapshotPath, `${guard.directory}/state.json`).status, 0);
              run('restore');
              assert.equal(prop(service, 'MainPID'), pid);
              assert.equal(prop(service, 'InvocationID'), invocation);
              assert.equal(exec('mv', `${guard.directory}/state.json`, `${guard.directory}/state.saved`).status, 0);
              assert.match(run('restore', false).stderr, /restore-evidence.json/);
              assert.equal(exec('test', '-f', `/var/lib/xcsh-csd-reservation/${service}.owner`).status, 0);
              const evidencePath = join(root, 'evidence.json');
              const evidence = {
                contract: 'xcsh-csd-restore-evidence-v1',
                externally_verified: true,
                reservation: snapshot,
              };
              await writeFile(
                evidencePath,
                JSON.stringify({
                  ...evidence,
                  reservation: { ...snapshot, run_id: randomUUID() },
                }),
              );
              assert.equal(
                exec('install', '-m', '700', evidencePath, `${guard.directory}/restore-evidence.json`).status,
                0,
              );
              assert.match(run('cleanup', false).stderr, /identity mismatch/);
              await writeFile(evidencePath, JSON.stringify(evidence));
              assert.equal(
                exec('install', '-m', '644', evidencePath, `${guard.directory}/restore-evidence.json`).status,
                0,
              );
              assert.match(run('restore', false).stderr, /unsafe reservation file/);
              assert.equal(
                exec('install', '-m', '700', evidencePath, `${guard.directory}/restore-evidence.json`).status,
                0,
              );
              run('restore');
              assert.equal(prop(service, 'MainPID'), pid);
              assert.equal(prop(service, 'InvocationID'), invocation);
            }
            // Cleanup is independently verified even if state.json claims restored.
            const blocker = (await import('node:child_process')).spawn(process.execPath, [
              '-e',
              'setTimeout(()=>{},20000)',
              '--',
              `--user-data-dir=/tmp/xcsh-csd-${runId}/probe-owned/profile`,
            ]);
            try {
              await new Promise((r) => setTimeout(r, 80));
              run('cleanup', false);
              assert.equal(prop(service, 'MainPID'), pid);
              assert.equal(prop(service, 'InvocationID'), invocation);
            } finally {
              blocker.kill();
              await new Promise((r) => blocker.once('exit', r));
            }
            run('restore');
            run('cleanup');
            assert.equal(prop(service, 'MainPID'), pid);
            assert.equal(prop(service, 'InvocationID'), invocation);
          } else {
            assert.equal(prop(service, 'ActiveState'), 'inactive');
            run('cleanup');
          }
          records.push({ enabled, active, serviceState, verified: true });
        } finally {
          // Only this UUID's isolated units/artifacts, including on the original red failure.
          for (const unit of [timer, service, `${guard.name}.timer`, `${guard.name}.service`]) {
            exec('systemctl', 'disable', '--now', unit);
            exec('systemctl', 'stop', unit);
          }
          exec(
            'rm',
            '-f',
            `/etc/systemd/system/${timer}`,
            `/etc/systemd/system/${service}`,
            `/etc/systemd/system/${guard.name}.timer`,
            `/etc/systemd/system/${guard.name}.service`,
          );
          exec('rm', '-rf', guard.directory, `/run/systemd/system/${guard.name}.timer.d`);
          exec(
            'rm',
            '-f',
            `/var/lib/xcsh-csd-reservation/${service}.owner`,
            `/var/lib/xcsh-csd-reservation/${service}.mutex`,
          );
          ctl('daemon-reload');
          await rm(root, { recursive: true, force: true });
        }
      }
  process.stdout.write(`DURABLE_ONESHOT_MATRIX=${JSON.stringify(records)}\n`);
});

test('Linux durable retained oneshot restores originally active service coherently', {
  skip: process.env.XCSH_CSD_LINUX_FIXTURES !== '1',
  timeout: 120_000,
}, async () => {
  const { randomUUID } = await import('node:crypto');
  const { rm } = await import('node:fs/promises');
  const { renderReservation } = await import('../scripts/lib/csd-page-tamper-reservation.mjs');
  for (const serviceState of ['static', 'disabled', 'enabled'])
    for (const timerActive of [false, true]) {
      const runId = randomUUID(),
        name = `xcsh-csd-fixture-${runId}`;
      const service = `${name}.service`,
        timer = `${name}.timer`;
      const guard = renderReservation({
        runId,
        service,
        timer,
        fixture: true,
        lifetimeSeconds: 120,
      });
      const root = await mkdtemp(join(tmpdir(), 'csd-retained-'));
      const script = join(root, 'guard.py');
      const exec = (...args) => spawnSync('sudo', ['-n', ...args], { encoding: 'utf8' });
      const ctl = (...args) => {
        const r = exec('systemctl', ...args);
        assert.equal(r.status, 0, r.stderr);
        return r.stdout.trim();
      };
      const run = (mode) => {
        const r = exec('python3', script, mode);
        assert.equal(r.status, 0, r.stderr);
      };
      const prop = (unit, field) => ctl('show', unit, '-p', field, '--value');
      await writeFile(script, guard.script);
      await writeFile(
        join(root, service),
        `[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/bin/sh -c 'echo "$INVOCATION_ID" >> ${root}/invocations; echo complete >> ${root}/completions'\n${serviceState === 'static' ? '' : '[Install]\nWantedBy=multi-user.target\n'}`,
      );
      await writeFile(
        join(root, timer),
        `[Timer]\nOnActiveSec=1ms\nUnit=${service}\n[Install]\nWantedBy=timers.target\n`,
      );
      assert.equal(
        exec('install', '-m', '644', join(root, service), join(root, timer), '/etc/systemd/system/').status,
        0,
      );
      ctl('daemon-reload');
      try {
        if (serviceState === 'enabled') ctl('enable', service);
        ctl('start', service);
        if (timerActive) ctl('start', timer);
        run('arm');
        run('restore');
        assert.equal(prop(service, 'ActiveState'), 'active');
        assert.equal(prop(service, 'UnitFileState'), serviceState);
        assert.equal(prop(timer, 'ActiveState'), timerActive ? 'active' : 'inactive');
        assert.equal(prop(timer, 'UnitFileState'), 'disabled');
        const invocation = prop(service, 'InvocationID');
        const snapshotPath = join(root, 'snapshot.json');
        assert.equal(exec('install', '-m', '644', `${guard.directory}/state.json`, snapshotPath).status, 0);
        const snapshot = JSON.parse(await readFile(snapshotPath, 'utf8'));
        for (const phase of ['prepared', 'service_intent', 'timer_intent']) {
          const interruptedPath = join(root, 'interrupted.json');
          await writeFile(interruptedPath, JSON.stringify({ ...snapshot, phase, restored: false }));
          assert.equal(exec('install', '-m', '700', interruptedPath, `${guard.directory}/state.json`).status, 0);
          run('restore');
          assert.equal(prop(service, 'InvocationID'), invocation);
        }
        run('restore');
        run('cleanup');
        assert.equal(prop(service, 'InvocationID'), invocation);
        assert.equal((await readFile(join(root, 'completions'), 'utf8')).trim().split('\n').length, 2);
        // Missing terminal state never means success by itself. The fixture's
        // independent verifier authors this receipt only after real cleanup probes.
        assert.notEqual(exec('python3', script, 'cleanup').status, 0);
        const evidencePath = join(root, 'evidence.json');
        const destination = `/var/lib/xcsh-csd-reservation/${runId}.restore-evidence.json`;
        for (const suffix of ['timer', 'service'])
          assert.equal(prop(`${guard.name}.${suffix}`, 'LoadState'), 'not-found');
        assert.equal(exec('test', '-e', guard.directory).status, 1);
        assert.equal(exec('test', '-e', `/var/lib/xcsh-csd-reservation/${service}.owner`).status, 1);
        await writeFile(
          evidencePath,
          JSON.stringify({
            contract: 'xcsh-csd-restore-evidence-v1',
            externally_verified: true,
            cleanup_complete: true,
            reservation: snapshot,
          }),
        );
        assert.equal(exec('install', '-m', '700', evidencePath, destination).status, 0);
        run('cleanup');
        run('restore');
        run('cleanup');
        assert.equal(prop(service, 'InvocationID'), invocation);
      } finally {
        for (const unit of [timer, service, `${guard.name}.timer`, `${guard.name}.service`]) {
          exec('systemctl', 'disable', '--now', unit);
          exec('systemctl', 'stop', unit);
        }
        exec(
          'rm',
          '-f',
          `/etc/systemd/system/${timer}`,
          `/etc/systemd/system/${service}`,
          `/etc/systemd/system/${guard.name}.timer`,
          `/etc/systemd/system/${guard.name}.service`,
        );
        exec('rm', '-rf', guard.directory, `/run/systemd/system/${guard.name}.timer.d`);
        exec(
          'rm',
          '-f',
          `/var/lib/xcsh-csd-reservation/${service}.owner`,
          `/var/lib/xcsh-csd-reservation/${service}.mutex`,
        );
        exec('rm', '-f', `/var/lib/xcsh-csd-reservation/${runId}.restore-evidence.json`);
        ctl('daemon-reload');
        await rm(root, { recursive: true, force: true });
      }
    }
});

test('recover-only without a lock performs no dependency calls', async () => {
  const { recoverOnly } = await import('../scripts/lib/csd-page-tamper-controller.mjs');
  const root = await workspace();
  const forbidden = () => {
    throw new Error('unexpected recovery side effect');
  };
  const result = await recoverOnly(
    config(root),
    deps({
      executor: forbidden,
      probe: forbidden,
      workerProbe: forbidden,
      randomUUID: forbidden,
      reservationRecovery: forbidden,
    }),
  );
  assert.equal(result.no_op, true);
});

test('recover-only rejects experimental options and requires environment-only authentication', async () => {
  const { parseArgs } = await import('../scripts/csd-page-tamper.mjs');
  for (const option of ['--header', '--browser-mode', '--placement', '--cdp-endpoint'])
    assert.throws(() => parseArgs(['recover-only', option, 'value'], {}), /rejects/);
  assert.throws(() => parseArgs(['recover-only', '--f5-api-token', 'value'], {}), /unknown option/);
  const env = {
    AWS_PROFILE: 'fixture',
    AWS_REGION: 'us-east-1',
    XCSH_CSD_AWS_ACCOUNT: '280469140135',
    XCSH_CSD_TERRAFORM_DIR: '/fixture',
    XCSH_CSD_TRAFFIC_GENERATOR_TERRAFORM_DIR: '/fixture',
    XCSH_API_URL: config('/fixture').f5ApiUrl,
    XCSH_NAMESPACE: 'client-side-defense',
    XCSH_LB_NAME: 'client-side-defense',
    XCSH_CSD_PAGE_TAMPER_RECEIPT_DIR: '/fixture',
  };
  assert.throws(() => parseArgs(['recover-only'], env), /f5ApiToken/);
  assert.equal(parseArgs(['recover-only'], { ...env, XCSH_API_TOKEN: 'fixture' }).command, 'recover-only');
});

async function interruptedCanaryFixture() {
  const root = await workspace();
  const c = config(root, { workerInstance: 'i-0123456789abcdef0' });
  const runId = '00000000-0000-4000-8000-000000000001';
  const identity = {
    runId,
    root: `/tmp/xcsh-csd-${runId}`,
    instance_id: c.workerInstance,
    aws_account: c.awsAccount,
    aws_region: c.awsRegion,
    aws_profile: c.awsProfile,
  };
  await mkdir(c.receiptDir);
  const lock = {
    schema_version: 2,
    run_id: runId,
    worker_run_id: runId,
    worker_identity: identity,
    command: 'canary',
    recovery_kind: 'canary',
    started_at: START,
    state: 'recovery-required',
  };
  await writeFile(join(c.receiptDir, 'active.lock'), JSON.stringify(lock));
  return { c, identity, lock };
}

function recoveryReport(identity, action) {
  return {
    schema_version: 1,
    worker_identity: identity,
    externally_verified: true,
    restoration: { restored: true, original_states_preserved: true },
    worker_artifacts_removed: action === 'cleanup',
    reservation_artifacts_removed: action === 'cleanup',
  };
}

test('interrupted canary performs ordered restore and cleanup without preparation, probe or run UUID', async () => {
  const { recoverOnly } = await import('../scripts/lib/csd-page-tamper-controller.mjs');
  const { c, identity } = await interruptedCanaryFixture();
  const actions = [];
  const forbidden = () => {
    throw new Error('fresh pipeline forbidden');
  };
  const result = await recoverOnly(
    c,
    deps({
      randomUUID: forbidden,
      probe: forbidden,
      workerProbe: forbidden,
      readiness: forbidden,
      reservationRecovery: async (action, owner) => {
        assert.deepEqual(owner, identity);
        actions.push(action);
        return recoveryReport(owner, action);
      },
      cleanup: async () => {
        actions.push('worker-cleanup');
        return {
          worker_artifacts_removed: true,
          browser_artifacts_removed: true,
        };
      },
    }),
  );
  assert.equal(result.success, true);
  assert.deepEqual(actions, ['restore', 'worker-cleanup', 'cleanup']);
  assert.equal((await status(c)).active, false);
});

test('interrupted canary rejects missing identity, mismatched evidence and cleanup failure retaining lock', async () => {
  const { recoverOnly } = await import('../scripts/lib/csd-page-tamper-controller.mjs');
  for (const fault of ['identity', 'evidence', 'truthy', 'cleanup']) {
    const { c, identity, lock } = await interruptedCanaryFixture();
    if (fault === 'identity') {
      delete lock.worker_identity;
      await writeFile(join(c.receiptDir, 'active.lock'), JSON.stringify(lock));
    }
    const actions = [];
    await assert.rejects(
      recoverOnly(
        c,
        deps({
          reservationRecovery: async (action, owner) => {
            actions.push(action);
            const value = recoveryReport(owner, action);
            if (fault === 'evidence')
              value.worker_identity = {
                ...identity,
                aws_account: '000000000000',
              };
            if (fault === 'truthy') value.restoration.restored = 'yes';
            return value;
          },
          cleanup: async () => ({
            worker_artifacts_removed: fault !== 'cleanup',
            browser_artifacts_removed: true,
          }),
        }),
      ),
    );
    const retained = JSON.parse(await readFile(join(c.receiptDir, 'active.lock'), 'utf8'));
    assert.equal(retained.recovery_kind, 'canary');
    assert.equal(retained.state, 'recovery-required');
    assert.ok(!actions.includes('cleanup'));
  }
});

test('canary recovery persists classification and evidence through receipt failure and retry', async () => {
  const { recoverOnly } = await import('../scripts/lib/csd-page-tamper-controller.mjs');
  const { rm } = await import('node:fs/promises');
  const { c, identity } = await interruptedCanaryFixture();
  let block;
  const verifier = async (action) => {
    if (action === 'cleanup' && !block) {
      block = join(c.receiptDir, `recovery-${identity.runId}-`);
      // Make atomicReceipt fail only after the guard cleanup was externally verified.
      const original = Date.now;
      Date.now = () => 42;
      block += '42.json';
      await mkdir(block);
      verifier.reset = () => {
        Date.now = original;
      };
    }
    return recoveryReport(identity, action);
  };
  try {
    await assert.rejects(
      recoverOnly(c, deps({ reservationRecovery: verifier })),
      (error) => error.code === 'EVIDENCE_PERSISTENCE_FAILED',
    );
  } finally {
    verifier.reset?.();
  }
  const retained = JSON.parse(await readFile(join(c.receiptDir, 'active.lock'), 'utf8'));
  assert.equal(retained.recovery_kind, 'canary');
  assert.equal(retained.recovery_evidence.reservation_artifacts_removed, true);
  assert.equal(retained.evidence_persistence_failure, true);
  await rm(block, { recursive: true });
  await assert.rejects(stat(join(c.receiptDir, 'recovery.claim')), /ENOENT/);
  const retry = await recoverOnly(
    c,
    deps({
      reservationRecovery: async (action) => recoveryReport(identity, action),
    }),
  );
  assert.equal(retry.success, true);
  assert.equal((await status(c)).active, false);
});

test('production RECOVERY helper transport chunks every SSM parameter below 4096 bytes', async () => {
  const { recoverOnly } = await import('../scripts/lib/csd-page-tamper-controller.mjs');
  const { c, identity } = await interruptedCanaryFixture();
  const scripts = [];
  let current;
  const base = executor();
  const injected = deps({
    executor: async (argv, options) => {
      if (argv[1] !== 'ssm') return base(argv, options);
      if (argv[2] === 'send-command') {
        const parameters = argv[argv.indexOf('--parameters') + 1];
        assert.ok(Buffer.byteLength(parameters) <= 4096);
        current = JSON.parse(parameters).commands[0];
        assert.ok(Buffer.byteLength(current) <= 4096);
        scripts.push(current);
        return {
          code: 0,
          stdout: JSON.stringify({ Command: { CommandId: 'fixture-command' } }),
          stderr: '',
        };
      }
      const action = current.endsWith("'cleanup'") ? 'cleanup' : 'restore';
      return {
        code: 0,
        stdout: JSON.stringify({
          Status: 'Success',
          ResponseCode: 0,
          StandardOutputContent: `XCSH_RESULT ${JSON.stringify(recoveryReport(identity, action))}`,
        }),
        stderr: '',
      };
    },
  });
  assert.equal((await recoverOnly(c, injected)).success, true);
  const chunks = scripts.filter((s) => s.includes("os.write(f,b'"));
  assert.ok(chunks.length > 4);
  assert.ok(scripts.some((s) => s.includes(`/var/lib/xcsh-csd-recovery/${identity.runId}/helper.py`)));
  assert.ok(scripts.some((s) => s.includes('canonical_directory(p,True)')));
  assert.doesNotMatch(scripts.join('\n'), /chown ubuntu|secret-not-for-receipts|Authorization/);
  const install = scripts.find((s) => s.includes("os.rename(name,'helper.py'"));
  const stage = install.match(/os.open\('([^']+)\/payload'/)[1];
  const payload = chunks
    .filter((s) => s.includes(`python3 - '${stage}'`))
    .map((s) => s.match(/os.write\(f,b'([^']+)'\)/)[1])
    .join('');
  const helper = Buffer.from(payload, 'base64').toString();
  assert.match(helper, /def external/);
  assert.match(helper, /probe_cleanup\(\)/);
  assert.match(helper, /externally_verified/);
});

test('Linux independent recovery helper validates missing-state authority, private ownership and retained dispatch', {
  skip: process.env.XCSH_CSD_RECOVERY_FIXTURES !== '1',
  timeout: 90_000,
}, async () => {
  const { randomUUID } = await import('node:crypto');
  const { rm } = await import('node:fs/promises');
  const { renderReservation } = await import('../scripts/lib/csd-page-tamper-reservation.mjs');
  const { renderCanaryRecoveryHelper } = await import('../scripts/lib/csd-page-tamper-controller.mjs');
  const runId = randomUUID();
  const service = `xcsh-csd-fixture-recovery-${runId}.service`;
  const timer = service.replace('.service', '.timer');
  const guard = renderReservation({
    runId,
    service,
    timer,
    lifetimeSeconds: 300,
    fixture: true,
  });
  const local = await mkdtemp(join(tmpdir(), 'csd-recovery-proof-'));
  const recoveryRoot = `/var/lib/xcsh-csd-recovery/${runId}`;
  const helperPath = `${recoveryRoot}/helper.py`;
  const identity = {
    runId,
    root: `/tmp/xcsh-csd-${runId}`,
    instance_id: 'i-0123456789abcdef0',
    aws_account: '280469140135',
    aws_region: 'us-east-1',
    aws_profile: 'fixture',
  };
  const exec = (...args) => spawnSync('sudo', ['-n', ...args], { encoding: 'utf8', timeout: 30_000 });
  const ok = (...args) => {
    const r = exec(...args);
    assert.equal(r.status, 0, r.stderr);
    return r.stdout.trim();
  };
  const ctl = (...args) => ok('systemctl', ...args);
  const prop = (unit, name) => ctl('show', unit, '-p', name, '--value');
  const helper = (action, success = true) => {
    const r = exec('python3', helperPath, action);
    if (success) assert.equal(r.status, 0, r.stderr);
    else assert.notEqual(r.status, 0);
    return r;
  };
  await writeFile(join(local, 'guard.py'), guard.script);
  await writeFile(join(local, 'helper.py'), renderCanaryRecoveryHelper(identity, { service, timer, fixture: true }));
  await writeFile(
    join(local, service),
    '[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=/usr/bin/true\n[Install]\nWantedBy=multi-user.target\n',
  );
  await writeFile(join(local, timer), `[Timer]\nOnActiveSec=1h\nUnit=${service}\n[Install]\nWantedBy=timers.target\n`);
  try {
    ok('install', '-m', '644', join(local, service), join(local, timer), '/etc/systemd/system/');
    ctl('daemon-reload');
    ctl('disable', timer, service);
    ctl('start', service);
    assert.equal(prop(service, 'ActiveState'), 'active');
    ok('install', '-d', '-m', '700', '/var/lib/xcsh-csd-recovery', recoveryRoot);
    ok('install', '-m', '700', join(local, 'helper.py'), helperPath);
    ok('python3', join(local, 'guard.py'), 'arm');
    helper('restore');
    assert.equal(prop(service, 'ActiveState'), 'active');
    assert.equal(prop(timer, 'ActiveState'), 'inactive');
    const start = prop(service, 'ExecMainStartTimestampMonotonic');
    assert.equal(ok('stat', '-c', '%u:%a', helperPath), '0:700');
    assert.equal(ok('stat', '-c', '%u:%a', `${guard.directory}/guard.py`), '0:700');
    const ubuntu = spawnSync('id', ['-u', 'ubuntu'], { encoding: 'utf8' });
    const unprivilegedUid = ubuntu.status === 0 ? Number(ubuntu.stdout.trim()) : process.getuid();
    assert.notEqual(unprivilegedUid, 0);
    const denied = exec('-u', `#${unprivilegedUid}`, 'python3', helperPath, 'restore');
    assert.notEqual(denied.status, 0);
    // Preserve the exact independently verified original BEFORE deleting state.
    ok(
      'python3',
      '-c',
      `import json,os,pathlib\nr=pathlib.Path('${guard.directory}')\ne={'contract':'xcsh-csd-restore-evidence-v1','externally_verified':True,'reservation':json.loads((r/'state.json').read_text())}\np=r/'restore-evidence.json'\np.write_text(json.dumps(e));p.chmod(0o700)\n(r/'state.json').unlink()\npathlib.Path('${recoveryRoot}/verified.json').unlink()`,
    );
    const evidencePath = `${guard.directory}/restore-evidence.json`;
    for (const mutation of [
      "e['externally_verified']='true'",
      "e['reservation']['run_id']='wrong'",
      "e['reservation']['phase']='resumed'",
      "e['reservation']['service']='wrong.service'",
      `e['reservation']['${timer}']['Triggers']='wrong.service'`,
      `e['reservation']['${service}']['Type']='simple'`,
    ]) {
      ok(
        'python3',
        '-c',
        `import json,pathlib\np=pathlib.Path('${evidencePath}');raw=p.read_text();e=json.loads(raw)\n${mutation}\np.with_suffix('.backup').write_text(raw);p.with_suffix('.backup').chmod(0o700);p.write_text(json.dumps(e))`,
      );
      helper('restore', false);
      assert.equal(prop(service, 'ExecMainStartTimestampMonotonic'), start);
      ok(
        'python3',
        '-c',
        `import pathlib\np=pathlib.Path('${evidencePath}');p.write_text(p.with_suffix('.backup').read_text());p.with_suffix('.backup').unlink()`,
      );
    }
    ok('chown', `${unprivilegedUid}:${unprivilegedUid}`, evidencePath);
    helper('restore', false);
    ok('chown', 'root:root', evidencePath);
    ok('chmod', '600', evidencePath);
    helper('restore', false);
    ok('chmod', '700', evidencePath);
    ok('python3', '-c', `import pathlib\np=pathlib.Path('${evidencePath}');p.rename(p.with_suffix('.saved'))`);
    helper('restore', false);
    ok('python3', '-c', `import pathlib\np=pathlib.Path('${evidencePath}');p.symlink_to(p.with_suffix('.saved'))`);
    helper('restore', false);
    ok(
      'python3',
      '-c',
      `import pathlib\np=pathlib.Path('${evidencePath}');p.unlink();p.with_suffix('.saved').rename(p)`,
    );
    const ownerPath = `/var/lib/xcsh-csd-reservation/${service}.owner`;
    ok('python3', '-c', `import pathlib\npathlib.Path('${ownerPath}').write_text('wrong-owner')`);
    helper('restore', false);
    ok('python3', '-c', `import pathlib\npathlib.Path('${ownerPath}').write_text('${runId}')`);
    helper('restore');
    assert.equal(prop(service, 'ExecMainStartTimestampMonotonic'), start);
    ok('install', '-d', '-m', '700', identity.root);
    helper('cleanup', false);
    assert.equal(prop(service, 'ExecMainStartTimestampMonotonic'), start);
    ok('rmdir', identity.root);
    helper('cleanup');
    helper('restore');
    helper('cleanup');
    assert.equal(prop(service, 'ExecMainStartTimestampMonotonic'), start);
    assert.equal(prop(service, 'ActiveState'), 'active');
    assert.equal(prop(service, 'UnitFileState'), 'disabled');
    ok(
      'python3',
      '-c',
      `import pathlib\nassert not pathlib.Path('${guard.directory}').exists()\nassert not pathlib.Path('${identity.root}').exists()\nassert not pathlib.Path('/var/lib/xcsh-csd-reservation/${service}.owner').exists()`,
    );
  } finally {
    exec('systemctl', 'disable', '--now', timer, service, `${guard.name}.timer`);
    exec('systemctl', 'stop', `${guard.name}.service`);
    ok(
      'rm',
      '-f',
      `/etc/systemd/system/${service}`,
      `/etc/systemd/system/${timer}`,
      `/etc/systemd/system/${guard.name}.timer`,
      `/etc/systemd/system/${guard.name}.service`,
      `/var/lib/xcsh-csd-reservation/${service}.owner`,
      `/var/lib/xcsh-csd-reservation/${service}.mutex`,
    );
    ok('rm', '-rf', guard.directory, recoveryRoot, identity.root, `/run/systemd/system/${guard.name}.timer.d`);
    ctl('daemon-reload');
    await rm(local, { recursive: true, force: true });
  }
});

test('Linux real service start failure retains intent and retries after repair without reinvocation', {
  skip: process.env.XCSH_CSD_LINUX_FIXTURES !== '1',
  timeout: 90_000,
}, async () => {
  const { randomUUID } = await import('node:crypto');
  const { rm } = await import('node:fs/promises');
  const { renderReservation } = await import('../scripts/lib/csd-page-tamper-reservation.mjs');
  for (const stage of ['ExecStartPre', 'ExecStart']) {
    const runId = randomUUID();
    const service = `xcsh-csd-fixture-${runId}.service`;
    const timer = `xcsh-csd-fixture-${runId}.timer`;
    const guard = renderReservation({
      runId,
      service,
      timer,
      fixture: true,
      lifetimeSeconds: 300,
    });
    const local = await mkdtemp(join(tmpdir(), 'csd-start-retry-'));
    const privateRoot = `/var/lib/xcsh-csd-reservation/fixture-${runId}`;
    const exec = (...args) => spawnSync('sudo', ['-n', ...args], { encoding: 'utf8' });
    const ok = (...args) => {
      const result = exec(...args);
      assert.equal(result.status, 0, result.stderr);
      return result.stdout.trim();
    };
    const ctl = (...args) => ok('systemctl', ...args);
    const prop = (unit, field) => ctl('show', unit, '-p', field, '--value');
    const run = (action) => exec('python3', join(local, 'guard.py'), action);
    const checkpoint = async () => {
      ok('install', '-m', '700', `${guard.directory}/state.json`, join(local, 'checkpoint.json'));
      ok('chown', `${process.getuid()}:${process.getgid()}`, join(local, 'checkpoint.json'));
      return JSON.parse(await readFile(join(local, 'checkpoint.json'), 'utf8'));
    };
    await writeFile(join(local, 'guard.py'), guard.script, { mode: 0o700 });
    await writeFile(
      join(local, 'execute.sh'),
      `#!/bin/sh\necho attempt >> '${privateRoot}/attempts'\n[ ! -e '${privateRoot}/fail' ] || exit 23\necho complete >> '${privateRoot}/completions'\n`,
      { mode: 0o700 },
    );
    await writeFile(
      join(local, service),
      `[Unit]\nStartLimitIntervalSec=0\n[Service]\nType=oneshot\nRemainAfterExit=yes\n${stage}=${privateRoot}/execute.sh\n${stage === 'ExecStartPre' ? 'ExecStart=/bin/true\n' : ''}[Install]\nWantedBy=multi-user.target\n`,
    );
    await writeFile(
      join(local, timer),
      `[Timer]\nOnActiveSec=1h\nUnit=${service}\n[Install]\nWantedBy=timers.target\n`,
    );
    try {
      ok('install', '-d', '-m', '700', privateRoot);
      ok('install', '-m', '700', join(local, 'execute.sh'), `${privateRoot}/execute.sh`);
      ok('install', '-m', '644', join(local, service), join(local, timer), '/etc/systemd/system/');
      ctl('daemon-reload');
      ctl('enable', service, timer);
      ctl('start', service, timer);
      assert.equal(run('arm').status, 0);
      ok('install', '-m', '700', '/dev/null', `${privateRoot}/fail`);
      const failed = run('restore');
      assert.notEqual(failed.status, 0);
      assert.match(failed.stderr, /systemd operation failed: start/);
      assert.equal(prop(service, 'ActiveState'), 'failed');
      assert.equal((await checkpoint()).phase, 'service_intent');
      assert.equal(prop(timer, 'ActiveState'), 'inactive');
      const failedAgain = run('restore');
      assert.notEqual(failedAgain.status, 0);
      assert.equal((await checkpoint()).phase, 'service_intent');
      assert.equal(prop(timer, 'ActiveState'), 'inactive');
      ok('rm', `${privateRoot}/fail`);
      const restored = run('restore');
      assert.equal(restored.status, 0, restored.stderr);
      assert.equal((await checkpoint()).phase, 'complete');
      assert.equal(prop(service, 'ActiveState'), 'active');
      assert.equal(prop(service, 'Result'), 'success');
      assert.equal(prop(service, 'ExecMainStatus'), '0');
      assert.equal(prop(timer, 'ActiveState'), 'active');
      const invocation = prop(service, 'InvocationID');
      const attempts = ok('wc', '-l', `${privateRoot}/attempts`);
      for (let retry = 0; retry < 2; retry++) {
        const result = run('restore');
        assert.equal(result.status, 0, result.stderr);
        assert.equal(prop(service, 'InvocationID'), invocation);
        assert.equal(ok('wc', '-l', `${privateRoot}/attempts`), attempts);
      }
      assert.match(ok('wc', '-l', `${privateRoot}/completions`), /^2 /);
      assert.equal(ok('stat', '-c', '%u:%a', privateRoot), '0:700');
      for (const path of [guard.directory, `${guard.directory}/state.json`, `${guard.directory}/guard.py`])
        assert.equal(ok('stat', '-c', '%u:%a', path), '0:700');
      assert.equal(run('cleanup').status, 0);
    } finally {
      for (const unit of [timer, service, `${guard.name}.timer`, `${guard.name}.service`]) {
        exec('systemctl', 'disable', '--now', unit);
        exec('systemctl', 'stop', unit);
      }
      ok(
        'rm',
        '-f',
        ...[timer, service, `${guard.name}.timer`, `${guard.name}.service`].map(
          (unit) => `/etc/systemd/system/${unit}`,
        ),
      );
      ok('rm', '-rf', guard.directory, privateRoot, `/run/systemd/system/${guard.name}.timer.d`);
      ok(
        'rm',
        '-f',
        `/var/lib/xcsh-csd-reservation/${service}.owner`,
        `/var/lib/xcsh-csd-reservation/${service}.mutex`,
      );
      ctl('daemon-reload');
      await rm(local, { recursive: true, force: true });
    }
  }
});

test('recover-only accepts suite-cleanup lock and releases it after verified cleanup', async () => {
  const { recoverOnly } = await import('../scripts/lib/csd-page-tamper-controller.mjs');
  const { rm } = await import('node:fs/promises');
  const root = await workspace();
  const c = config(root);
  await mkdir(c.receiptDir);
  await writeFile(
    join(c.receiptDir, 'active.lock'),
    JSON.stringify({
      run_id: 'suite-owner',
      command: 'suite-cleanup',
      worker_run_id: null,
      started_at: START,
      state: 'recovery-required',
    }),
  );
  try {
    const result = await recoverOnly(c, deps());
    assert.equal(result.success, true);
    assert.equal((await status(c)).active, false);
    assert.ok((await readdir(c.receiptDir)).some((name) => name.startsWith('recovery-suite-owner-')));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

for (const child of ['bootstrap', 'header']) {
  test(`canary child receipt failure preserves owning run id for ${child} recovery`, async () => {
    const { recoverOnly, bindLocalLock, closeLocalLock } = await import(
      '../scripts/lib/csd-page-tamper-controller.mjs'
    );
    const { rm } = await import('node:fs/promises');
    const childId = '00000000-0000-4000-8000-000000000002';
    const { c, identity, lock } = await interruptedCanaryFixture();
    const block =
      child === 'bootstrap'
        ? join(c.receiptDir, `bootstrap-${childId}.json`)
        : join(c.receiptDir, `${START.replace(/[:.]/g, '-')}-x-content-type-options-${childId}.json`);
    // Reuse atomicReceipt's existing directory-at-destination failure injection.
    await mkdir(block);
    try {
      const injected = deps({
        randomUUID: () => childId,
        alertSource: async () => [],
      });
      const options = {
        lockPath: join(c.receiptDir, 'active.lock'),
        worker: identity,
        finalizeWorker: false,
      };
      await bindLocalLock(options.lockPath, lock);
      await assert.rejects(
        child === 'bootstrap'
          ? bootstrap(c, injected, options)
          : runHeader(c, injected, 'x-content-type-options', options),
        (error) => error.code === 'EVIDENCE_PERSISTENCE_FAILED',
      );
      const retained = JSON.parse(await readFile(options.lockPath, 'utf8'));
      assert.equal(retained.run_id, lock.run_id);
      assert.equal(retained.worker_run_id, identity.runId);
      assert.equal(retained.command, 'canary');
      assert.equal(retained.recovery_kind, 'canary');
      assert.deepEqual(retained.worker_identity, identity);
      assert.equal(retained.evidence_persistence_failure, undefined);
      await closeLocalLock(options.lockPath);
      const actions = [];
      const result = await recoverOnly(
        c,
        deps({
          reservationRecovery: async (action, owner) => {
            assert.deepEqual(owner, identity);
            actions.push(action);
            return recoveryReport(owner, action);
          },
        }),
      );
      assert.equal(result.success, true);
      assert.deepEqual(actions, ['restore', 'cleanup']);
      assert.equal((await status(c)).active, false);
    } finally {
      await rm(c.receiptDir, { recursive: true, force: true });
      await rm(join(c.terraformDir, '..'), { recursive: true, force: true });
    }
  });
}

test('Linux prearm descriptor mutex filesystem contract', {
  skip: process.env.XCSH_CSD_PREARM_FIXTURES !== '1',
  timeout: 60_000,
}, async () => {
  const { randomUUID } = await import('node:crypto');
  const { rm } = await import('node:fs/promises');
  const { WORKER_MUTEX_PROTOCOL, renderReservation } = await import('../scripts/lib/csd-page-tamper-reservation.mjs');
  assert.equal(process.platform, 'linux');
  const runId = randomUUID();
  const service = `xcsh-csd-fixture-mutex-${runId}.service`;
  const guard = renderReservation({
    runId,
    service,
    timer: service.replace('.service', '.timer'),
    lifetimeSeconds: 60,
    fixture: true,
  });
  const local = await mkdtemp(join(tmpdir(), 'csd-mutex-proof-'));
  const mutex = `/var/lib/xcsh-csd-reservation/${service}.mutex`;
  const exec = (...args) => spawnSync('sudo', ['-n', ...args], { encoding: 'utf8', timeout: 10_000 });
  const ok = (...args) => {
    const r = exec(...args);
    assert.equal(r.status, 0, r.stderr);
    return r.stdout.trim();
  };
  const script = join(local, 'mutex.py');
  await writeFile(script, `${guard.script.split('owner=parent/')[0]}\nprint("LOCKED")\n`);
  try {
    ok('install', '-d', '-m', '700', '/var/lib/xcsh-csd-reservation');
    ok('install', '-m', '644', '/dev/null', mutex);
    const inode = ok('stat', '-c', '%d:%i', mutex);
    ok('python3', script);
    assert.equal(ok('stat', '-c', '%u:%a:%h:%s', mutex), '0:600:1:0');
    assert.equal(ok('stat', '-c', '%d:%i', mutex), inode);
    ok('rm', '-f', mutex);
    ok('python3', script);
    assert.equal(ok('stat', '-c', '%u:%a:%h:%s', mutex), '0:600:1:0');
    for (const mode of ['666', '700', '755']) {
      ok('chmod', mode, mutex);
      assert.notEqual(exec('python3', script).status, 0);
      assert.equal(ok('stat', '-c', '%a', mutex), mode);
    }
    ok('chmod', '600', mutex);
    ok('chown', '65534:65534', mutex);
    assert.notEqual(exec('python3', script).status, 0);
    assert.equal(ok('stat', '-c', '%u', mutex), '65534');
    ok('chown', 'root:root', mutex);
    ok('ln', mutex, `${mutex}.link`);
    assert.notEqual(exec('python3', script).status, 0);
    ok('rm', '-f', `${mutex}.link`);
    ok('python3', '-c', `import pathlib;pathlib.Path('${mutex}').write_text('unsafe')`);
    assert.notEqual(exec('python3', script).status, 0);
    ok('rm', '-f', mutex);
    ok('ln', '-s', '/dev/null', mutex);
    assert.notEqual(exec('python3', script).status, 0);
    assert.equal(ok('readlink', mutex), '/dev/null');
    ok('rm', '-f', mutex);
    ok('install', '-m', '644', '/dev/null', mutex);
    const held = exec('flock', '-x', mutex, 'python3', script);
    assert.notEqual(held.status, 0);
    assert.equal(ok('stat', '-c', '%a', mutex), '644');
    const isolated = `/var/lib/xcsh-csd-fixture-parent-${runId}`;
    try {
      ok('install', '-d', '-m', '755', isolated);
      const acquire = `${WORKER_MUTEX_PROTOCOL}\nreservation_mutex(pathlib.Path('${isolated}'),'fixture.service')`;
      assert.notEqual(exec('python3', '-c', `import os,pathlib\n${acquire}`).status, 0);
      assert.equal(ok('stat', '-c', '%a', isolated), '755');
      ok('chmod', '700', isolated);
      ok('ln', '-s', isolated, `${isolated}.link`);
      assert.notEqual(
        exec(
          'python3',
          '-c',
          `import os,pathlib\n${WORKER_MUTEX_PROTOCOL}\nreservation_mutex(pathlib.Path('${isolated}.link'),'fixture.service')`,
        ).status,
        0,
      );
      // Replace the pathname after flock: repair must not chmod either inode.
      const replacement = `import os,pathlib\n${WORKER_MUTEX_PROTOCOL}\noriginal=fcntl.flock\ndef race(fd,flags):\n original(fd,flags)\n p=pathlib.Path('${isolated}/fixture.service.mutex');p.rename(p.with_suffix('.old'));p.touch(mode=0o644)\nfcntl.flock=race\nreservation_mutex(pathlib.Path('${isolated}'),'fixture.service')`;
      ok('install', '-m', '644', '/dev/null', `${isolated}/fixture.service.mutex`);
      assert.notEqual(exec('python3', '-c', replacement).status, 0);
      assert.equal(ok('stat', '-c', '%a', `${isolated}/fixture.service.old`), '644');
      assert.equal(ok('stat', '-c', '%a', `${isolated}/fixture.service.mutex`), '644');
    } finally {
      ok('rm', '-f', `${isolated}.link`);
      ok('rm', '-rf', isolated);
    }
  } finally {
    ok('rm', '-f', mutex, `${mutex}.link`);
    await rm(local, { recursive: true, force: true });
  }
});

test('prearm recovery requires worker proof even after an ambiguous arm attempt', async () => {
  const { recoverOnly } = await import('../scripts/lib/csd-page-tamper-controller.mjs');
  for (const localPhase of ['prepare_intent', 'arm_intent']) {
    const { c, identity, lock } = await interruptedCanaryFixture();
    await writeFile(join(c.receiptDir, 'active.lock'), JSON.stringify({ ...lock, canary_phase: localPhase }));
    const actions = [];
    const result = await recoverOnly(
      c,
      deps({
        reservationRecovery: async (action) => {
          actions.push(action);
          return {
            schema_version: 1,
            externally_verified: true,
            worker_identity: identity,
            prearm: true,
            restoration: { restored: false, required: false },
            worker_artifacts_removed: true,
            reservation_artifacts_removed: true,
          };
        },
        workerProbe: () => {
          throw new Error('prearm must not probe');
        },
        cleanup: () => {
          throw new Error('prearm must not run target cleanup');
        },
      }),
    );
    assert.deepEqual(actions, ['classify', 'prearm']);
    assert.equal(result.recovery.efficacy, 'NOT_TESTED');
    assert.deepEqual(result.recovery.restoration, {
      restored: false,
      required: false,
    });
    assert.equal((await status(c)).active, false);
  }
});

test('prearm missing worker journal retains local lock rather than inferring absence', async () => {
  const { recoverOnly } = await import('../scripts/lib/csd-page-tamper-controller.mjs');
  const { c, lock } = await interruptedCanaryFixture();
  await writeFile(join(c.receiptDir, 'active.lock'), JSON.stringify({ ...lock, canary_phase: 'arm_intent' }));
  await assert.rejects(
    recoverOnly(
      c,
      deps({
        reservationRecovery: async () => {
          throw new Error('prearm journal missing');
        },
      }),
    ),
    /journal missing/,
  );
  assert.equal((await status(c)).active, true);
});

test('Linux prearm durable exception crash replay and armed denial', {
  skip: process.env.XCSH_CSD_PREARM_FIXTURES !== '1',
  timeout: 90_000,
}, async () => {
  const { randomUUID } = await import('node:crypto');
  const { rm } = await import('node:fs/promises');
  const { renderCanaryRecoveryHelper } = await import('../scripts/lib/csd-page-tamper-controller.mjs');
  const { renderReservation } = await import('../scripts/lib/csd-page-tamper-reservation.mjs');
  assert.equal(process.platform, 'linux');
  const runId = randomUUID();
  const service = `xcsh-csd-fixture-prearm-${runId}.service`;
  const timer = service.replace('.service', '.timer');
  const identity = {
    runId,
    root: `/tmp/xcsh-csd-${runId}`,
    instance_id: 'i-0123456789abcdef0',
    aws_account: '280469140135',
    aws_region: 'us-east-1',
    aws_profile: 'fixture',
  };
  const guard = renderReservation({
    runId,
    service,
    timer,
    lifetimeSeconds: 300,
    fixture: true,
  });
  const local = await mkdtemp(join(tmpdir(), 'csd-prearm-proof-'));
  const directory = `/var/lib/xcsh-csd-recovery/${runId}`;
  const journal = `${directory}/lifecycle.json`;
  const exec = (...args) => spawnSync('sudo', ['-n', ...args], { encoding: 'utf8', timeout: 20_000 });
  const ok = (...args) => {
    const r = exec(...args);
    assert.equal(r.status, 0, r.stderr);
    return r.stdout.trim();
  };
  const helperPath = join(local, 'helper.py');
  const rendered = renderCanaryRecoveryHelper(identity, {
    service,
    timer,
    fixture: true,
  });
  await writeFile(helperPath, rendered);
  const helper = (action) => JSON.parse(ok('python3', helperPath, action).split('XCSH_RESULT ')[1]);
  try {
    ok('install', '-d', '-m', '700', '/var/lib/xcsh-csd-reservation');
    // No historical authority: fresh absence alone does not authorize rollback.
    assert.notEqual(exec('python3', helperPath, 'prearm').status, 0);
    helper('initialize');
    helper('prepare');
    assert.equal(helper('classify').prearm, true);
    // Real hard exit after durable cleanup intent, before deleting the owned root.
    const crash = join(local, 'crash.py');
    await writeFile(crash, rendered.replace("shutil.rmtree('worker',dir_fd=qfd)", 'os._exit(77)'));
    const crashed = exec('python3', crash, 'prearm');
    assert.equal(crashed.status, 77, crashed.stderr);
    assert.equal(helper('prearm').restoration.restored, false);
    assert.equal(helper('prearm').worker_artifacts_removed, true);
    // A second real hard exit occurs after deletion, before completion journaling.
    ok(
      'python3',
      '-c',
      `import json,pathlib;p=pathlib.Path('${journal}');v=json.loads(p.read_text());v['phase']='NOT_ARMED';v.pop('root_inode',None);p.write_text(json.dumps(v))`,
    );
    helper('prepare');
    await writeFile(
      crash,
      rendered.replace("shutil.rmtree('worker',dir_fd=qfd)", "shutil.rmtree('worker',dir_fd=qfd);os._exit(78)"),
    );
    assert.equal(exec('python3', crash, 'prearm').status, 78);
    assert.equal(helper('prearm').reservation_artifacts_removed, true);
    // ARM_INTENT is deliberately irreversible even if an exception preceded snapshot.
    ok(
      'python3',
      '-c',
      `import json,pathlib;p=pathlib.Path('${journal}');v=json.loads(p.read_text());v['phase']='ARM_INTENT';p.write_text(json.dumps(v))`,
    );
    assert.equal(helper('classify').prearm, false);
    assert.notEqual(exec('python3', helperPath, 'prearm').status, 0);
    assert.notEqual(exec('python3', helperPath, 'restore').status, 0);
    // Fresh authority with a reservation snapshot or guard unit is never prearm.
    ok(
      'python3',
      '-c',
      `import json,pathlib;p=pathlib.Path('${journal}');v=json.loads(p.read_text());v['phase']='NOT_ARMED';p.write_text(json.dumps(v))`,
    );
    ok('install', '-d', '-m', '700', guard.directory);
    assert.notEqual(exec('python3', helperPath, 'prearm').status, 0);
    ok('rmdir', guard.directory);
    ok('install', '-m', '644', '/dev/null', `/etc/systemd/system/${guard.name}.service`);
    assert.notEqual(exec('python3', helperPath, 'prearm').status, 0);
  } finally {
    ok('rm', '-f', `/etc/systemd/system/${guard.name}.service`, `/var/lib/xcsh-csd-reservation/${service}.mutex`);
    ok('rm', '-rf', directory, identity.root, guard.directory);
    await rm(local, { recursive: true, force: true });
  }
});

test('prearm canary arm exception persists phase before side effects and cleans without restore', async () => {
  const { runCanary } = await import('../scripts/lib/csd-page-tamper-controller.mjs');
  const root = await workspace();
  const c = config(root, { browserMode: 'headed-xvfb', placement: 'worker' });
  const actions = [];
  await assert.rejects(
    runCanary(
      c,
      deps({
        reservation: async (action) => {
          const lock = JSON.parse(await readFile(join(c.receiptDir, 'active.lock'), 'utf8'));
          assert.equal(lock.canary_phase, 'arm_intent');
          assert.equal(action, 'arm');
          throw new Error('arm transport exception');
        },
        reservationRecovery: async (action, worker_identity) => {
          actions.push(action);
          const lock = JSON.parse(await readFile(join(c.receiptDir, 'active.lock'), 'utf8'));
          if (action === 'initialize') assert.equal(lock.canary_phase, 'initialize_intent');
          return {
            schema_version: 1,
            externally_verified: true,
            worker_identity,
            prearm: true,
            restoration: { restored: false, required: false },
            worker_artifacts_removed: true,
            reservation_artifacts_removed: true,
          };
        },
        probe: () => {
          throw new Error('no prearm probe permitted');
        },
      }),
    ),
    /arm transport exception/,
  );
  assert.deepEqual(actions, ['initialize', 'classify', 'prearm']);
  assert.equal((await status(c)).active, false);
});

test('prearm canary source preparation exception retains NOT_TESTED recovery receipt', async () => {
  const { runCanary } = await import('../scripts/lib/csd-page-tamper-controller.mjs');
  const root = await workspace();
  const c = config(root, { browserMode: 'headed-xvfb', placement: 'worker' });
  const actions = [];
  await assert.rejects(
    runCanary(
      c,
      deps({
        workerProbe: undefined,
        readFile: async () => {
          const lock = JSON.parse(await readFile(join(c.receiptDir, 'active.lock'), 'utf8'));
          assert.equal(lock.canary_phase, 'prepare_intent');
          throw new Error('source preparation exception');
        },
        reservation: () => {
          throw new Error('must not arm');
        },
        reservationRecovery: async (action, worker_identity) => {
          actions.push(action);
          return {
            schema_version: 1,
            externally_verified: true,
            worker_identity,
            prearm: true,
            restoration: { restored: false, required: false },
            worker_artifacts_removed: true,
            reservation_artifacts_removed: true,
          };
        },
      }),
    ),
    /source preparation exception/,
  );
  assert.deepEqual(actions, ['initialize', 'classify', 'prearm']);
  assert.equal((await status(c)).active, false);
  const receipt = JSON.parse(
    await readFile(join(c.receiptDir, 'canary-00000000-0000-4000-8000-000000000001-failed.json'), 'utf8'),
  );
  assert.equal(receipt.efficacy, 'NOT_TESTED');
  assert.equal(receipt.recovery.restoration.restored, false);
  assert.equal(Object.hasOwn(receipt, 'worker_identity'), false);
});

test('owned local lock rejects inode and run substitution without touching foreign lock', async () => {
  const { acquireLock, releaseOwnedLock } = await import('../scripts/lib/csd-page-tamper-controller.mjs');
  const { rename, rm } = await import('node:fs/promises');
  const root = await workspace();
  const c = config(root);
  const path = await acquireLock(c, 'owned-run', () => START, 'run');
  await rename(path, `${path}.owned`);
  const foreign = JSON.stringify({ run_id: 'foreign', worker_run_id: null });
  await writeFile(path, foreign);
  await assert.rejects(releaseOwnedLock(path), /ownership changed/);
  assert.equal(await readFile(path, 'utf8'), foreign);
  await rm(path);
  await rename(`${path}.owned`, path);
  await writeFile(path, foreign);
  await assert.rejects(releaseOwnedLock(path), /run binding changed/);
  await writeFile(
    path,
    JSON.stringify({
      schema_version: 2,
      run_id: 'owned-run',
      command: 'run',
      worker_run_id: null,
      started_at: START,
      state: 'active',
    }),
  );
  await releaseOwnedLock(path);
});

test('durable receipt fsyncs file and directory before owned lock release', async () => {
  const { atomicReceipt, acquireLock, releaseOwnedLock } = await import(
    '../scripts/lib/csd-page-tamper-controller.mjs'
  );
  const root = await workspace();
  const c = config(root);
  const path = await acquireLock(c, 'durable-run', () => START, 'run');
  const probe = await import('node:fs/promises');
  const handle = await probe.open(path, 'r');
  const prototype = Object.getPrototypeOf(handle);
  await handle.close();
  const sync = prototype.sync;
  let calls = 0;
  prototype.sync = async function () {
    calls += 1;
    if (calls === 1) throw new Error('injected file fsync failure');
    return sync.call(this);
  };
  try {
    await assert.rejects(atomicReceipt(join(c.receiptDir, 'failed.json'), { success: true }), /fsync failure/);
    assert.equal((await status(c)).active, true);
  } finally {
    prototype.sync = sync;
  }
  calls = 0;
  prototype.sync = async function () {
    calls += 1;
    if (calls === 2) throw new Error('injected directory fsync failure');
    return sync.call(this);
  };
  try {
    await assert.rejects(
      atomicReceipt(join(c.receiptDir, 'directory-failed.json'), {
        success: true,
      }),
      /directory fsync failure/,
    );
    assert.equal((await status(c)).active, true);
  } finally {
    prototype.sync = sync;
  }
  await atomicReceipt(join(c.receiptDir, 'complete.json'), { success: true });
  calls = 0;
  prototype.sync = async function () {
    calls += 1;
    if (calls === 1) throw new Error('unlink directory sync failure');
    return sync.call(this);
  };
  try {
    await assert.rejects(releaseOwnedLock(path), /authority retained/);
    assert.equal((await status(c)).active, true);
  } finally {
    prototype.sync = sync;
  }
  assert.equal(JSON.parse(await readFile(join(c.receiptDir, 'complete.json'), 'utf8')).success, true);
});

test('prearm initialize failure retains lock and releases terminal recovery claim', async () => {
  const { runCanary } = await import('../scripts/lib/csd-page-tamper-controller.mjs');
  const root = await workspace();
  const c = config(root, { browserMode: 'headed-xvfb', placement: 'worker' });
  const actions = [];
  await assert.rejects(
    runCanary(
      c,
      deps({
        reservationRecovery: async (action) => {
          actions.push(action);
          throw new Error('journal unavailable');
        },
      }),
    ),
    /unverified/,
  );
  assert.deepEqual(actions, ['initialize', 'classify']);
  assert.equal((await status(c)).active, true);
});

test('Linux worker inode quarantine and privileged install preserve replacement sentinels', {
  skip: process.env.XCSH_CSD_PREARM_FIXTURES !== '1',
  timeout: 90_000,
}, async () => {
  const { randomUUID } = await import('node:crypto');
  const { renderCanaryRecoveryHelper, installWorkerFile } = await import(
    '../scripts/lib/csd-page-tamper-controller.mjs'
  );
  const runId = randomUUID();
  const service = `xcsh-csd-fixture-sentinel-${runId}.service`;
  const timer = service.replace('.service', '.timer');
  const identity = {
    runId,
    root: `/tmp/xcsh-csd-${runId}`,
    instance_id: 'i-0123456789abcdef0',
    aws_account: '280469140135',
    aws_region: 'us-east-1',
    aws_profile: 'fixture',
  };
  const local = await mkdtemp(join(tmpdir(), 'csd-sentinel-'));
  const helperPath = join(local, 'helper.py');
  await writeFile(helperPath, renderCanaryRecoveryHelper(identity, { service, timer, fixture: true }));
  const execute = (...args) => spawnSync('sudo', ['-n', ...args], { encoding: 'utf8', timeout: 30_000 });
  const ok = (...args) => {
    const r = execute(...args);
    assert.equal(r.status, 0, r.stderr);
    return r;
  };
  const helper = (mode) => ok('python3', helperPath, mode);
  let invocation;
  const injected = createDependencies({
    executor: async (argv) => {
      if (argv[2] === 'send-command') {
        const script = JSON.parse(argv[argv.indexOf('--parameters') + 1]).commands[0];
        const r = execute('/bin/sh', '-c', script);
        invocation = {
          Status: r.status === 0 ? 'Success' : 'Failed',
          ResponseCode: r.status,
          StandardOutputContent: r.stdout,
          StandardErrorContent: r.stderr,
        };
        return {
          code: 0,
          stdout: JSON.stringify({ Command: { CommandId: randomUUID() } }),
        };
      }
      return { code: 0, stdout: JSON.stringify(invocation) };
    },
  });
  const workerConfig = config(local, {
    workerInstance: identity.instance_id,
  });
  try {
    helper('initialize');
    helper('prepare');
    ok(
      'python3',
      '-c',
      `import os,pathlib;p=pathlib.Path('${identity.root}');(p/'sentinel').write_text('KEEP');os.symlink(p/'sentinel',p/'payload.py')`,
    );
    await assert.rejects(installWorkerFile(workerConfig, injected, `${identity.root}/payload.py`, 'TRUNCATE'), /SSM/);
    assert.equal(ok('python3', '-c', `print(open('${identity.root}/sentinel').read())`).stdout.trim(), 'KEEP');
    ok(
      'python3',
      '-c',
      `import os,pathlib;p=pathlib.Path('${identity.root}');os.rename(p,str(p)+'.original');p.mkdir(mode=0o755);(p/'sentinel').write_text('REPLACEMENT')`,
    );
    assert.notEqual(execute('python3', helperPath, 'prearm').status, 0);
    assert.equal(ok('python3', '-c', `print(open('${identity.root}/sentinel').read())`).stdout.trim(), 'REPLACEMENT');
    await assert.rejects(installWorkerFile(workerConfig, injected, `${identity.root}/payload.py`, 'TRUNCATE'), /SSM/);
    ok(
      'python3',
      '-c',
      `import os,shutil;shutil.rmtree('${identity.root}');os.symlink('${identity.root}.original','${identity.root}')`,
    );
    assert.notEqual(execute('python3', helperPath, 'prearm').status, 0);
    assert.equal(ok('python3', '-c', `print(open('${identity.root}.original/sentinel').read())`).stdout.trim(), 'KEEP');
    ok(
      'python3',
      '-c',
      `import os;os.unlink('${identity.root}');os.rename('${identity.root}.original','${identity.root}')`,
    );
    helper('prearm');
    const devices = ok(
      'python3',
      '-c',
      "import os;print(os.stat('/tmp').st_dev,os.stat('/var/lib').st_dev)",
    ).stdout.trim();
    process.stdout.write(`QUARANTINE_SENTINEL=passed INSTALL_SENTINEL=passed FILESYSTEM_DEVICES=${devices}\n`);
  } finally {
    ok(
      'python3',
      '-c',
      `import os,shutil;paths=['${identity.root}','${identity.root}.original','/tmp/.xcsh-csd-quarantine-${runId}','/var/lib/xcsh-csd-recovery/${runId}'];[(os.unlink(p) if os.path.islink(p) else shutil.rmtree(p)) for p in paths if os.path.lexists(p)]`,
    );
    ok('rm', '-f', `/var/lib/xcsh-csd-reservation/${service}.mutex`);
  }
});

test('Linux armed guard preserves substituted worker root and symlink sentinels', {
  skip: process.env.XCSH_CSD_PREARM_FIXTURES !== '1',
  timeout: 60_000,
}, async () => {
  const { randomUUID } = await import('node:crypto');
  const { renderCanaryRecoveryHelper } = await import('../scripts/lib/csd-page-tamper-controller.mjs');
  const { renderReservation } = await import('../scripts/lib/csd-page-tamper-reservation.mjs');
  const runId = randomUUID();
  const service = `xcsh-csd-fixture-armed-${runId}.service`;
  const timer = service.replace('.service', '.timer');
  const identity = {
    runId,
    root: `/tmp/xcsh-csd-${runId}`,
    instance_id: 'i-0123456789abcdef0',
    aws_account: '280469140135',
    aws_region: 'us-east-1',
    aws_profile: 'fixture',
  };
  const local = await mkdtemp(join(tmpdir(), 'csd-armed-sentinel-'));
  const helper = join(local, 'helper.py');
  const guard = renderReservation({
    runId,
    service,
    timer,
    lifetimeSeconds: 300,
    fixture: true,
  });
  const guardPath = join(local, 'guard.py');
  await writeFile(helper, renderCanaryRecoveryHelper(identity, { service, timer, fixture: true }));
  await writeFile(guardPath, guard.script);
  await writeFile(
    join(local, service),
    '[Service]\nType=oneshot\nExecStart=/usr/bin/true\n[Install]\nWantedBy=multi-user.target\n',
  );
  await writeFile(join(local, timer), `[Timer]\nOnActiveSec=1h\nUnit=${service}\n[Install]\nWantedBy=timers.target\n`);
  const execute = (...args) => spawnSync('sudo', ['-n', ...args], { encoding: 'utf8', timeout: 30_000 });
  const ok = (...args) => {
    const r = execute(...args);
    assert.equal(r.status, 0, r.stderr);
    return r;
  };
  try {
    ok('install', '-m', '644', join(local, service), join(local, timer), '/etc/systemd/system/');
    ok('systemctl', 'daemon-reload');
    ok('python3', helper, 'initialize');
    ok('python3', helper, 'prepare');
    ok('python3', guardPath, 'arm');
    ok(
      'python3',
      '-c',
      `import os,pathlib;p=pathlib.Path('${identity.root}');os.rename(p,str(p)+'.original');p.mkdir(mode=0o755);(p/'sentinel').write_text('ARMED KEEP')`,
    );
    assert.notEqual(execute('python3', guardPath, 'restore').status, 0);
    assert.equal(ok('python3', '-c', `print(open('${identity.root}/sentinel').read())`).stdout.trim(), 'ARMED KEEP');
    ok(
      'python3',
      '-c',
      `import os,shutil;shutil.rmtree('${identity.root}');os.symlink('${identity.root}.original','${identity.root}')`,
    );
    assert.notEqual(execute('python3', guardPath, 'restore').status, 0);
    ok(
      'python3',
      '-c',
      `import os;os.unlink('${identity.root}');os.rename('${identity.root}.original','${identity.root}')`,
    );
    ok('python3', guardPath, 'restore');
    ok('python3', guardPath, 'cleanup');
    process.stdout.write('ARMED_REPLACEMENT_SENTINEL=passed ARMED_SYMLINK_SENTINEL=passed\n');
  } finally {
    execute('systemctl', 'disable', '--now', `${guard.name}.timer`, timer);
    execute('systemctl', 'stop', `${guard.name}.service`, service);
    ok(
      'python3',
      '-c',
      `import os,shutil;files=['/etc/systemd/system/${service}','/etc/systemd/system/${timer}','/etc/systemd/system/${guard.name}.service','/etc/systemd/system/${guard.name}.timer','/var/lib/xcsh-csd-reservation/${service}.owner','/var/lib/xcsh-csd-reservation/${service}.mutex'];[os.unlink(p) for p in files if os.path.lexists(p)];paths=['${identity.root}','${identity.root}.original','/tmp/.xcsh-csd-quarantine-${runId}','/var/lib/xcsh-csd-recovery/${runId}','${guard.directory}','/run/systemd/system/${guard.name}.timer.d'];[(os.unlink(p) if os.path.islink(p) else shutil.rmtree(p)) for p in paths if os.path.lexists(p)]`,
    );
    ok('systemctl', 'daemon-reload');
  }
});

test('Linux worker quarantine uses separate tmp filesystem without copy fallback', {
  skip: process.env.XCSH_CSD_PREARM_FIXTURES !== '1',
  timeout: 30_000,
}, async () => {
  const { randomUUID } = await import('node:crypto');
  const { WORKER_MUTEX_PROTOCOL, WORKER_FILESYSTEM_PROTOCOL } = await import(
    '../scripts/lib/csd-page-tamper-reservation.mjs'
  );
  const runId = randomUUID();
  const script = `import json,os,pathlib,stat,shutil\n${WORKER_MUTEX_PROTOCOL}\n${WORKER_FILESYSTEM_PROTOCOL}\nrun='${runId}';p=pathlib.Path('/tmp/xcsh-csd-'+run);p.mkdir(mode=0o755);os.chmod(p,0o755);s=p.stat();j=pathlib.Path('/var/lib/xcsh-csd-recovery')/run\nos.close(canonical_directory(j.parent,True));os.close(canonical_directory(j,True));fd=os.open(j/'lifecycle.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o700)\nwith os.fdopen(fd,'w') as f: json.dump({'contract':'xcsh-csd-prearm-v1','worker_identity':{'runId':run,'root':str(p)},'root_inode':[s.st_dev,s.st_ino]},f);f.flush();os.fsync(f.fileno())\nassert os.stat('/tmp').st_dev!=os.stat('/var/lib').st_dev\nworker_quarantine(run);assert not p.exists();worker_quarantine(run);print('SEPARATE_TMP_QUARANTINE=passed');shutil.rmtree(j)\n`;
  const r = spawnSync(
    'sudo',
    ['-n', 'unshare', '--mount', '/bin/sh', '-c', 'mount -t tmpfs -o mode=1777 tmpfs /tmp && exec python3 -'],
    { input: script, encoding: 'utf8', timeout: 20_000 },
  );
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /SEPARATE_TMP_QUARANTINE=passed/);
  process.stdout.write(r.stdout);
});

test('prearm phase rejects foreign lock substitution before arm and preserves foreign contents', async () => {
  const { runCanary } = await import('../scripts/lib/csd-page-tamper-controller.mjs');
  const { rename, rm } = await import('node:fs/promises');
  const root = await workspace();
  const c = config(root, { browserMode: 'headed-xvfb', placement: 'worker' });
  const path = join(c.receiptDir, 'active.lock');
  const foreign = JSON.stringify({
    run_id: 'foreign',
    worker_run_id: 'foreign',
    command: 'canary',
    started_at: START,
  });
  let arms = 0;
  await assert.rejects(
    runCanary(
      c,
      deps({
        reservationRecovery: async (action, identity) => {
          assert.equal(action, 'initialize');
          await rename(path, `${path}.original`);
          await writeFile(path, foreign);
          return {
            schema_version: 1,
            externally_verified: true,
            worker_identity: identity,
          };
        },
        reservation: async () => {
          arms += 1;
          throw new Error('unexpected arm');
        },
      }),
    ),
    /ownership changed/,
  );
  assert.equal(arms, 0);
  assert.equal(await readFile(path, 'utf8'), foreign);
  await rm(root, { recursive: true, force: true });
});

test('Linux worker-backed noncanary recovery preserves original authority across interrupted recovery', {
  skip: process.env.XCSH_CSD_PREARM_FIXTURES !== '1',
  timeout: 120_000,
}, async () => {
  const { randomUUID } = await import('node:crypto');
  const { prepareWorker, recoverOnly } = await import('../scripts/lib/csd-page-tamper-controller.mjs');
  const root = await workspace();
  const c = config(root, { workerInstance: 'i-0123456789abcdef0' });
  const base = executor();
  let invocation;
  const scripts = [];
  const real = async (argv, options) => {
    if (argv[1] !== 'ssm') return base(argv, options);
    if (argv[2] === 'send-command') {
      const script = JSON.parse(argv[argv.indexOf('--parameters') + 1]).commands[0];
      scripts.push(script);
      const r = spawnSync('sudo', ['-n', '/bin/sh', '-c', script], {
        encoding: 'utf8',
        timeout: 60_000,
      });
      invocation = {
        Status: r.status === 0 ? 'Success' : 'Failed',
        ResponseCode: r.status,
        StandardOutputContent: r.stdout,
        StandardErrorContent: r.stderr,
      };
      if (r.status !== 0) process.stderr.write(r.stderr);
      return {
        code: 0,
        stdout: JSON.stringify({ Command: { CommandId: randomUUID() } }),
      };
    }
    assert.equal(argv[2], 'get-command-invocation');
    return { code: 0, stdout: JSON.stringify(invocation) };
  };
  const original = await prepareWorker(c, deps({ executor: real, workerProbe: null }), randomUUID());
  const journal = `/var/lib/xcsh-csd-recovery/${original.runId}/lifecycle.json`;
  const readAuthority = (path) =>
    JSON.parse(
      spawnSync('sudo', ['-n', 'python3', '-c', `print(open('${path}').read())`], { encoding: 'utf8' }).stdout,
    );
  const originalAuthority = readAuthority(journal);
  await writeFile(
    join(c.receiptDir, 'active.lock'),
    JSON.stringify({
      run_id: original.runId,
      worker_run_id: original.runId,
      command: 'run',
      state: 'recovery-required',
      started_at: START,
    }),
  ).catch(async (error) => {
    if (error.code !== 'ENOENT') throw error;
    await mkdir(c.receiptDir);
    await writeFile(
      join(c.receiptDir, 'active.lock'),
      JSON.stringify({
        run_id: original.runId,
        worker_run_id: original.runId,
        command: 'run',
        state: 'recovery-required',
        started_at: START,
      }),
    );
  });
  let pending;
  try {
    await assert.rejects(
      recoverOnly(
        c,
        deps({
          executor: real,
          workerProbe: null,
          cleanup: null,
          probe: () => {
            throw new Error('interrupted recovery control');
          },
        }),
      ),
      /interrupted recovery control/,
    );
    const lock = JSON.parse(await readFile(join(c.receiptDir, 'active.lock'), 'utf8'));
    pending = lock.recovery_worker_identity;
    assert.notEqual(pending.runId, original.runId);
    const binding = readAuthority(`/var/lib/xcsh-csd-recovery/${pending.runId}/lifecycle.json`).recovery_original;
    const { sha256, ...originalIdentity } = original;
    assert.deepEqual(binding.worker_identity, originalIdentity);
    assert.deepEqual(binding.root_inode, originalAuthority.root_inode);
    const result = await recoverOnly(c, deps({ executor: real, workerProbe: null, cleanup: null }));
    assert.equal(result.success, true);
    assert.notEqual(result.recovery.recovery_worker_identity.runId, pending.runId);
    await assert.rejects(stat(original.root), { code: 'ENOENT' });
    await assert.rejects(stat(pending.root), { code: 'ENOENT' });
    const retained = readAuthority(journal);
    assert.equal(retained.phase, originalAuthority.phase);
    assert.equal(retained.pause_intent, false);
    assert.deepEqual(retained.root_inode, originalAuthority.root_inode);
    assert.ok(scripts.every((s) => !s.includes('systemctl stop csd-continuous')));
    process.stdout.write('NONCANARY_INTERRUPTED_RECOVERY=passed ORIGINAL_AUTHORITY=preserved FRESH_IDENTITY=bound\n');
  } finally {
    const dirs = new Set([original.runId, pending?.runId]);
    for (const script of scripts) {
      const m = script.match(/\/var\/lib\/xcsh-csd-recovery\/([0-9a-f-]{36})/);
      if (m) dirs.add(m[1]);
    }
    for (const run of dirs)
      if (run) {
        const cleanup = spawnSync(
          'sudo',
          [
            '-n',
            'python3',
            '-c',
            `import pathlib,shutil\np=pathlib.Path('/var/lib/xcsh-csd-recovery/${run}');q=pathlib.Path('/tmp/.xcsh-csd-quarantine-${run}')\nassert not pathlib.Path('/tmp/xcsh-csd-${run}').exists()\nif p.exists(): shutil.rmtree(p)\nif q.exists(): q.rmdir()`,
          ],
          { encoding: 'utf8' },
        );
        assert.equal(cleanup.status, 0, cleanup.stderr);
      }
  }
});
