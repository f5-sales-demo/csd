import { spawn } from 'node:child_process';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { constants } from 'node:fs';
import { link, lstat, mkdir, open, readFile, rename, rm, stat, writeFile } from 'node:fs/promises';
import { basename, dirname, join } from 'node:path';
import { Readable, Writable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { fileURLToPath } from 'node:url';
import { createGzip } from 'node:zlib';
import { DOCUMENT_PROBE_HEADERS, DOCUMENT_PROBE_PATH, DOCUMENT_PROBE_SELECTOR_IDS } from './csd-config.mjs';
import { classifyAlerts, correlateAlertViews } from './csd-page-tamper-alerts.mjs';
import {
  renderHeadedProbe,
  renderReservation,
  reservationLifetime,
  WORKER_FILESYSTEM_PROTOCOL,
  WORKER_MUTEX_PROTOCOL,
} from './csd-page-tamper-reservation.mjs';
import { CdpClient, runDocumentProbe } from './csd-runner.mjs';

export const HEADER_VALUES = Object.freeze(
  Object.fromEntries(DOCUMENT_PROBE_HEADERS.map(({ id, value }) => [id, value])),
);
export const HEADER_IDS = DOCUMENT_PROBE_SELECTOR_IDS;
export const PAYMENT_PATH = DOCUMENT_PROBE_PATH;
export const DEFAULT_TIMINGS = Object.freeze({
  bootstrapControlMs: 45 * 60_000,
  quietMs: 15 * 60_000,
  reinforcementMs: 15 * 60_000,
  mixedMs: 45 * 60_000,
  recoveryMs: 15 * 60_000,
  maximumCaseMs: 90 * 60_000,
  pollMs: 60_000,
  commandTimeoutMs: 5 * 60_000,
  reinforcementProfiles: 12,
  minimumPairs: 20,
});
const REVIEWED = Object.freeze({
  targetOrigin: 'https://client-side-defense.f5-sales-demo.com',
  f5ApiOrigin: 'https://f5-sales-demo.console.ves.volterra.io',
  awsAccount: '280469140135',
  awsProfile: '280469140135_Users',
  awsRegion: 'us-east-1',
  namespace: 'client-side-defense',
  lbName: 'client-side-defense',
  backendBucket: 'terraform-tfstate-xc',
  backendKey: 'f5-sales-demo/client-side-defense.tfstate',
  workerBackendBucket: 'terraform-tfstate-xc',
  workerBackendKey: 'f5-sales-demo/traffic-generator-aws.tfstate',
  workerBackendRegion: 'us-east-1',
});
const MODULE_NAMES = ['csd-config.mjs', 'csd-scenarios.mjs', 'csd-runner.mjs'];

export class ControllerError extends Error {
  constructor(message, code = 'CONTROLLER_ERROR', exitCode = 4) {
    super(message);
    this.code = code;
    this.exitCode = exitCode;
  }
}

export function defaultExecutor(argv, { cwd, env, signal, timeoutMs = DEFAULT_TIMINGS.commandTimeoutMs } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(argv[0], argv.slice(1), {
      cwd,
      env,
      signal,
      shell: false,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const stdout = [];
    const stderr = [];
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      reject(new ControllerError(`${basename(argv[0])} command timed out`, 'EXTERNAL_COMMAND_TIMEOUT'));
    }, timeoutMs);
    child.stdout.on('data', (chunk) => stdout.push(chunk));
    child.stderr.on('data', (chunk) => stderr.push(chunk));
    child.once('error', (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.once('close', (code) => {
      clearTimeout(timer);
      resolve({
        code,
        stdout: Buffer.concat(stdout).toString(),
        stderr: Buffer.concat(stderr).toString(),
      });
    });
  });
}

const command = async (deps, argv, options = {}) => {
  const result = await deps.executor(argv, {
    ...options,
    timeoutMs: options.timeoutMs ?? deps.commandTimeoutMs,
  });
  if (result.code !== 0) throw new ControllerError(`${basename(argv[0])} command failed`, 'EXTERNAL_COMMAND_FAILED');
  return result.stdout;
};
const assertValue = (actual, expected, name) => {
  if (actual !== expected)
    throw new ControllerError(`${name} does not match the reviewed deployment`, 'IDENTITY_MISMATCH', 3);
};
const awsBase = (config) => ['--profile', config.awsProfile, '--region', config.awsRegion, '--output', 'json'];
const parseJson = (text, code) => {
  try {
    return JSON.parse(text);
  } catch {
    throw new ControllerError('external command returned invalid JSON', code);
  }
};

function backendSettings(source) {
  const block = source.match(/(?:^|[\n{])[ \t]*backend\s+"s3"\s*\{([^}]*)\}/s)?.[1];
  if (!block) return null;
  const values = {};
  for (const key of ['bucket', 'key', 'region']) {
    const matches = [
      ...block.matchAll(new RegExp(`^[ \\t]*${key}[ \\t]*=[ \\t]*"([^"]+)"[ \\t]*(?:#.*|\\/\\/.*)?$`, 'gm')),
    ];
    if (matches.length === 1) values[key] = matches[0][1];
  }
  return values;
}

export async function validateDeploymentIdentity(config, deps) {
  const target = new URL(config.target);
  assertValue(target.origin, REVIEWED.targetOrigin, 'target');
  assertValue(target.pathname, PAYMENT_PATH, 'target path');
  assertValue(config.awsAccount, REVIEWED.awsAccount, 'AWS account');
  assertValue(config.awsProfile, REVIEWED.awsProfile, 'AWS profile');
  assertValue(config.awsRegion, REVIEWED.awsRegion, 'AWS region');
  assertValue(config.namespace, REVIEWED.namespace, 'namespace');
  assertValue(config.lbName, REVIEWED.lbName, 'load balancer');
  assertValue(new URL(config.f5ApiUrl).origin, REVIEWED.f5ApiOrigin, 'F5 API origin');
  const versions = await readFile(join(config.terraformDir, 'versions.tf'), 'utf8');
  const csdBackend = backendSettings(versions);
  if (csdBackend?.bucket !== REVIEWED.backendBucket || csdBackend?.key !== REVIEWED.backendKey)
    throw new ControllerError('Terraform backend does not match the reviewed deployment', 'IDENTITY_MISMATCH', 3);

  const workerVersions = await readFile(join(config.trafficGeneratorTerraformDir, 'versions.tf'), 'utf8');
  const workerBackend = backendSettings(workerVersions);
  if (
    workerBackend?.bucket !== REVIEWED.workerBackendBucket ||
    workerBackend?.key !== REVIEWED.workerBackendKey ||
    workerBackend?.region !== REVIEWED.workerBackendRegion
  )
    throw new ControllerError(
      'traffic-generator Terraform backend does not match the reviewed worker state',
      'IDENTITY_MISMATCH',
      3,
    );
  const workerOutput = await command(
    deps,
    ['terraform', `-chdir=${config.trafficGeneratorTerraformDir}`, 'output', '-raw', 'instance_id'],
    { env: deps.env, signal: deps.signal },
  );
  const workerInstance = workerOutput.trim();
  if (!/^i-[0-9a-f]{8,17}$/.test(workerInstance))
    throw new ControllerError(
      'traffic-generator instance_id output is missing or invalid',
      'WORKER_IDENTITY_INVALID',
      5,
    );
  config.workerInstance = workerInstance;

  const caller = parseJson(
    await command(deps, ['aws', 'sts', 'get-caller-identity', '--profile', config.awsProfile, '--output', 'json']),
    'AWS_INVALID_JSON',
  );
  assertValue(String(caller.Account), REVIEWED.awsAccount, 'active AWS account');
  const worker = parseJson(
    await command(deps, ['aws', 'ec2', 'describe-instances', '--instance-ids', workerInstance, ...awsBase(config)]),
    'AWS_INVALID_JSON',
  );
  const instances = worker.Reservations?.flatMap(({ Instances = [] }) => Instances) || [];
  if (instances.length !== 1 || instances[0].InstanceId !== workerInstance || instances[0].State?.Name !== 'running')
    throw new ControllerError('worker instance is not the reviewed running worker', 'IDENTITY_MISMATCH', 3);

  const outputs = parseJson(
    await command(deps, ['terraform', `-chdir=${config.terraformDir}`, 'output', '-json'], {
      env: deps.env,
      signal: deps.signal,
    }),
    'TERRAFORM_INVALID_JSON',
  );
  assertValue(outputs.aws_account_id?.value, REVIEWED.awsAccount, 'Terraform AWS account');
  assertValue(outputs.aws_region?.value, REVIEWED.awsRegion, 'Terraform region');
  assertValue(outputs.application_url?.value, REVIEWED.targetOrigin, 'Terraform application URL');
  assertValue(outputs.xc_namespace?.value, REVIEWED.namespace, 'Terraform namespace');
  assertValue(outputs.xc_http_loadbalancer_name?.value, REVIEWED.lbName, 'Terraform load balancer');
  if (!outputs.page_tamper_target_group_arn?.value)
    throw new ControllerError('page tamper target group output is missing', 'IDENTITY_MISMATCH', 3);
  return outputs;
}

async function noDrift(config, deps) {
  const result = await deps.executor(
    ['terraform', `-chdir=${config.terraformDir}`, 'plan', '-detailed-exitcode', '-input=false', '-no-color'],
    { env: deps.env, signal: deps.signal, timeoutMs: deps.commandTimeoutMs },
  );
  return { checked: true, no_drift: result.code === 0 };
}

const SAFE_WORKER_RUN_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
function workerIdentity(config, worker) {
  if (worker === null) return null;
  const root = worker?.root;
  const runId = worker?.runId;
  if (
    typeof runId !== 'string' ||
    !SAFE_WORKER_RUN_ID.test(runId) ||
    root !== `/tmp/xcsh-csd-${runId}` ||
    !/^i-[0-9a-f]{8,17}$/.test(config.workerInstance)
  )
    throw new ControllerError('worker root or target identity cannot be proven', 'WORKER_IDENTITY_INVALID', 5);
  return {
    runId,
    root,
    instance_id: config.workerInstance,
    aws_account: config.awsAccount,
    aws_region: config.awsRegion,
    aws_profile: config.awsProfile,
  };
}
function validatedWorker(config, identity) {
  if (!identity || typeof identity !== 'object' || Array.isArray(identity))
    throw new ControllerError('recorded worker identity is missing', 'WORKER_IDENTITY_INVALID', 5);
  const expected = workerIdentity(config, identity);
  if (Object.keys(expected).some((key) => identity[key] !== expected[key]))
    throw new ControllerError('recorded worker target differs from active worker', 'WORKER_IDENTITY_INVALID', 5);
  return expected;
}

// A retained descriptor and kernel flock bind local authority to one inode.
const localLocks = new Map();
const sameInode = (a, b) => a.dev === b.dev && a.ino === b.ino;
export async function bindLocalLock(path, expected, inode = null) {
  if (localLocks.has(path)) throw new ControllerError('local lock already held', 'OVERLAP', 5);
  const handle = await open(path, constants.O_RDWR | constants.O_NOFOLLOW);
  let lease;
  try {
    const metadata = await handle.stat();
    if (!metadata.isFile() || metadata.nlink !== 1 || (inode && !sameInode(metadata, inode)))
      throw new ControllerError('local lock inode changed', 'OVERLAP', 5);
    lease = spawn(
      'python3',
      [
        '-c',
        "import os,sys,fcntl,stat;f=os.open(sys.argv[1],os.O_RDWR|os.O_NOFOLLOW);s=os.fstat(f);assert stat.S_ISREG(s.st_mode) and s.st_nlink==1 and [s.st_dev,s.st_ino]==[int(sys.argv[2]),int(sys.argv[3])];fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB);print('HELD',flush=True);sys.stdin.buffer.read();os.close(f)",
        path,
        String(metadata.dev),
        String(metadata.ino),
      ],
      { stdio: ['pipe', 'pipe', 'pipe'] },
    );
    await new Promise((resolve, reject) => {
      lease.once('error', reject);
      lease.once('exit', () => reject(new ControllerError('local lock is held or unavailable', 'OVERLAP', 5)));
      lease.stdout.once('data', (data) =>
        data.toString().trim() === 'HELD'
          ? resolve()
          : reject(new ControllerError('local exclusion unavailable', 'OVERLAP', 5)),
      );
    });
    localLocks.set(path, { handle, metadata, expected, lease });
    await ownedLocalLock(path, expected);
  } catch (error) {
    localLocks.delete(path);
    lease?.stdin.end();
    await handle.close();
    throw error;
  }
}
export async function closeLocalLock(path) {
  const owned = localLocks.get(path);
  if (!owned) return;
  localLocks.delete(path);
  owned.lease.stdin.end();
  await owned.handle.close();
}
async function ownedLocalLock(path, expected = null) {
  const owned = localLocks.get(path);
  if (!owned) throw new ControllerError('local lock lease unavailable', 'OVERLAP', 5);
  const metadata = await lstat(path);
  if (
    !sameInode(metadata, owned.metadata) ||
    !metadata.isFile() ||
    metadata.nlink !== 1 ||
    owned.lease.exitCode !== null
  )
    throw new ControllerError('local lock ownership changed', 'OVERLAP', 5);
  const current = await owned.handle.stat();
  const buffer = Buffer.alloc(current.size);
  const { bytesRead } = await owned.handle.read(buffer, 0, buffer.length, 0);
  if (bytesRead !== buffer.length || !sameInode(await lstat(path), owned.metadata))
    throw new ControllerError('local lock changed while reading', 'OVERLAP', 5);
  const value = JSON.parse(buffer.toString());
  const identity = expected || owned.expected;
  if (
    value.run_id !== identity.run_id ||
    value.worker_run_id !== identity.worker_run_id ||
    value.command !== identity.command ||
    value.started_at !== identity.started_at ||
    JSON.stringify(value.worker_identity) !== JSON.stringify(identity.worker_identity)
  )
    throw new ControllerError('local lock run binding changed', 'OVERLAP', 5);
  return value;
}
async function syncDirectory(path) {
  const directory = await open(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try {
    await directory.sync();
  } finally {
    await directory.close();
  }
}
export async function releaseOwnedLock(path) {
  const value = await ownedLocalLock(path);
  await rm(path);
  try {
    await syncDirectory(dirname(path));
  } catch {
    // Exclusive creation can retain our authority, never overwrite a replacement.
    const file = await open(path, 'wx', 0o600);
    try {
      await file.writeFile(`${JSON.stringify(value)}\n`);
      await file.sync();
    } finally {
      await file.close();
    }
    await closeLocalLock(path);
    throw new ControllerError('lock release durability failed; authority retained', 'EVIDENCE_PERSISTENCE_FAILED', 5);
  }
  await closeLocalLock(path);
}

export async function acquireLock(config, runId, now, commandName, worker = null) {
  const identity = workerIdentity(config, worker);
  await mkdir(config.receiptDir, { recursive: true, mode: 0o700 });
  const path = join(config.receiptDir, 'active.lock');
  let handle;
  try {
    handle = await open(path, 'wx+', 0o600);
    await handle.writeFile(
      `${JSON.stringify({
        schema_version: 2,
        run_id: runId,
        command: commandName,
        worker_run_id: identity?.runId || null,
        ...(commandName === 'canary'
          ? {
              recovery_kind: 'canary',
              worker_identity: identity,
              canary_phase: 'initialize_intent',
            }
          : {}),
        started_at: now(),
        state: 'active',
      })}\n`,
    );
    await handle.sync();
    const directory = await open(config.receiptDir, 'r');
    try {
      await directory.sync();
    } finally {
      await directory.close();
    }
    const inode = await handle.stat();
    const buffer = Buffer.alloc(inode.size);
    await handle.read(buffer, 0, buffer.length, 0);
    const expected = JSON.parse(buffer.toString());
    await bindLocalLock(path, expected, inode);
    return path;
  } catch (error) {
    if (error.code === 'EEXIST') throw new ControllerError('another Page Tamper experiment is active', 'OVERLAP', 5);
    throw error;
  } finally {
    await handle?.close();
  }
}

async function atomicReplace(path, value) {
  if (basename(path) === 'active.lock') {
    await ownedLocalLock(path, value);
    const previous = localLocks.get(path);
    const temp = join(dirname(path), `.${basename(path)}.${randomUUID()}.phase`);
    const file = await open(temp, 'wx+', 0o600);
    try {
      await file.writeFile(`${JSON.stringify(value, null, 2)}\n`);
      await file.sync();
    } finally {
      await file.close();
    }
    try {
      await bindLocalLock(temp, value);
      await ownedLocalLock(path, value);
      await rename(temp, path);
      localLocks.set(path, localLocks.get(temp));
      localLocks.delete(temp);
      previous.lease.stdin.end();
      await previous.handle.close();
      await syncDirectory(dirname(path));
      await ownedLocalLock(path, value);
    } catch (error) {
      await closeLocalLock(temp);
      await rm(temp, { force: true });
      throw error;
    }
    return;
  }
  const temp = join(dirname(path), `.${basename(path)}.${process.pid}.${randomUUID()}.tmp`);
  await writeFile(temp, `${JSON.stringify(value, null, 2)}\n`, {
    mode: 0o600,
    flag: 'wx',
  });
  const handle = await open(temp, 'r');
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
  await rename(temp, path);
  const directory = await open(dirname(path), 'r');
  try {
    await directory.sync();
  } finally {
    await directory.close();
  }
}
export async function atomicReceipt(path, value) {
  const temp = join(dirname(path), `.${basename(path)}.${process.pid}.${randomUUID()}.tmp`);
  try {
    const file = await open(temp, 'wx', 0o600);
    try {
      await file.writeFile(`${JSON.stringify(value, null, 2)}\n`);
      await file.sync();
    } finally {
      await file.close();
    }
    await link(temp, path);
    await syncDirectory(dirname(path));
  } finally {
    await rm(temp, { force: true });
    await syncDirectory(dirname(path));
  }
}
async function preserveRecoveryLock(lockPath, receipt, error, evidencePersistenceFailure = true) {
  try {
    const previous = await ownedLocalLock(lockPath);
    if (
      previous.run_id !== receipt.run_id ||
      (receipt.worker_run_id !== undefined && previous.worker_run_id !== receipt.worker_run_id)
    )
      throw new ControllerError('cannot preserve foreign local lock', 'OVERLAP', 5);
    await atomicReplace(lockPath, {
      ...previous,
      schema_version: 2,
      run_id: previous.run_id,
      command: previous.command,
      worker_run_id: previous.worker_run_id ?? receipt.worker_run_id ?? null,
      started_at: previous.started_at,
      state: 'recovery-required',
      recovery_completed: receipt.recovery?.success === true,
      evidence_persistence_failure: evidencePersistenceFailure,
      error: {
        code: error.code || 'RECEIPT_WRITE_FAILED',
        message: String(error.message).slice(0, 160),
      },
    });
  } finally {
    await closeLocalLock(lockPath);
  }
}

async function withRecoveryClaimGate(config, callback) {
  // The active.lock kernel lease serializes callers; never adopt a legacy gate.
  const gatePath = join(config.receiptDir, 'recovery.claim.guard');
  if (await lstat(gatePath).catch(() => null))
    throw new ControllerError('legacy recovery gate ownership unavailable', 'OVERLAP', 5);
  return callback();
}

async function claimRecovery(config, state, deps) {
  const path = join(config.receiptDir, 'recovery.claim');
  const ownerPath = join(path, 'owner.json');
  const claimId = state.command === 'canary' ? randomBytes(16).toString('hex') : deps.randomUUID();
  const value = {
    schema_version: 2,
    claim_id: claimId,
    run_id: state.run_id,
    original_command: state.command || null,
    original_started_at: state.started_at,
    claimed_at: deps.now(),
  };
  return withRecoveryClaimGate(config, async () => {
    try {
      await mkdir(path, { mode: 0o700 });
    } catch (error) {
      if (error.code !== 'EEXIST') throw error;
      const before = await lstat(path).catch(() => null);
      const owner = before ? await lstat(ownerPath) : null;
      if (!before?.isDirectory() || before.isSymbolicLink() || !owner?.isFile() || owner.nlink !== 1)
        throw new ControllerError('recovery claim filesystem ownership unavailable', 'OVERLAP', 5);
      const current = JSON.parse(await readFile(ownerPath, 'utf8'));
      if (
        current?.run_id !== state.run_id ||
        current?.original_command !== state.command ||
        current?.original_started_at !== state.started_at
      )
        throw new ControllerError('recovery claim run ownership unavailable', 'OVERLAP', 5);
      if (!before || deps.nowMs() - before.mtimeMs <= config.timings.maximumCaseMs)
        throw new ControllerError('interrupted recovery is already claimed', 'OVERLAP', 5);
      const after = await lstat(path).catch(() => null);
      if (!after || before.dev !== after.dev || before.ino !== after.ino || before.mtimeMs !== after.mtimeMs)
        throw new ControllerError('interrupted recovery claim changed during takeover', 'OVERLAP', 5);
      const preserved = join(
        config.receiptDir,
        `recovery-claim-stale-${state.run_id}-${deps.nowMs()}-${current?.claim_id || 'unknown'}.json`,
      );
      await atomicReceipt(preserved, current);
      await rm(path, { recursive: true });
      await mkdir(path, { mode: 0o700 });
    }
    await atomicReceipt(ownerPath, value);
    const inode = await lstat(path);
    return { path, ownerPath, claimId, inode };
  });
}

async function releaseRecoveryClaim(config, claim, deps) {
  return withRecoveryClaimGate(config, async () => {
    if (!sameInode(await lstat(claim.path), claim.inode))
      throw new ControllerError('recovery claim inode changed', 'OVERLAP', 5);
    const current = JSON.parse(await deps.readFile(claim.ownerPath, 'utf8'));
    if (current.claim_id !== claim.claimId) throw new ControllerError('recovery claim ownership changed', 'OVERLAP', 5);
    await deps.remove(claim.path, { recursive: true });
    await syncDirectory(config.receiptDir);
  });
}

function probeOptions(config, headerId) {
  return {
    target: config.target,
    ...(headerId ? { selector: headerId } : {}),
    timeoutMs: config.probeTimeoutMs,
    settleMs: config.probeSettleMs,
  };
}
function validProbe(probe, omitted = null) {
  const response = probe?.document;
  const headers = response?.headers || [];
  return (
    probe?.success === true &&
    response?.observed === true &&
    response.status === 200 &&
    headers.length === HEADER_IDS.length &&
    headers.every((item) =>
      item.name === omitted
        ? item.present === false && item.observed_value === null
        : item.present === true && item.expected_match === true && item.observed_value === item.expected_value,
    ) &&
    Array.isArray(response.fields_present) &&
    response.fields_present.length === 5 &&
    response.fields_empty === true &&
    probe.instrumentation?.imp_apg_present === true &&
    probe.instrumentation?.dip_post_observed === true &&
    probe.cleanup?.target_closed !== false &&
    probe.cleanup?.context_disposed !== false &&
    probe.cleanup?.listeners_removed !== false
  );
}

async function connectCdp(config, deps) {
  const endpoint = new URL(config.cdpEndpoint);
  if (!['localhost', '127.0.0.1', '::1', '[::1]'].includes(endpoint.hostname))
    throw new ControllerError('CDP endpoint must be loopback', 'CDP_UNSAFE', 3);
  const response = await deps.fetch(new URL('/json/version', endpoint), {
    signal: deps.signal,
  });
  if (!response.ok) throw new ControllerError('Chrome discovery failed', 'CDP_DISCOVERY_FAILED', 3);
  const websocket = new URL((await response.json()).webSocketDebuggerUrl);
  if (websocket.protocol !== 'ws:' || !['localhost', '127.0.0.1', '::1', '[::1]'].includes(websocket.hostname))
    throw new ControllerError('Chrome returned an unsafe WebSocket URL', 'CDP_UNSAFE', 3);
  return CdpClient.connect(websocket.href, config.probeTimeoutMs, deps.WebSocket, deps.signal);
}

function ssmArgs(config, ...args) {
  return ['aws', 'ssm', ...args, ...awsBase(config)];
}
const SSM_COMMAND_LIMIT = 4096;

function workerArchiveEntries(sources) {
  return Object.entries(sources)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([name, body]) => `${name.length}:${name}${body.length}:${body}`)
    .join('');
}

async function gzipBuffer(value) {
  const chunks = [];
  const sink = new Writable({
    write(chunk, _encoding, callback) {
      chunks.push(chunk);
      callback();
    },
  });
  await pipeline(Readable.from([value]), createGzip({ level: 9, mtime: 0 }), sink);
  return Buffer.concat(chunks);
}

async function workerSources(deps) {
  const directory = dirname(fileURLToPath(import.meta.url));
  return Object.fromEntries(
    await Promise.all(MODULE_NAMES.map(async (name) => [name, await deps.readFile(join(directory, name), 'utf8')])),
  );
}

function assertSsmParameters(parameters) {
  const serialized = JSON.stringify(parameters);
  if (serialized.length > SSM_COMMAND_LIMIT || parameters.commands.some((item) => item.length > SSM_COMMAND_LIMIT))
    throw new ControllerError('generated SSM command exceeds AWS-RunShellScript plugin limit', 'SSM_COMMAND_TOO_LARGE');
  return serialized;
}

async function invokeSsm(config, deps, script, { expectResult = false } = {}) {
  if (
    JSON.stringify({ commands: [script], executionTimeout: [String(Math.ceil(deps.commandTimeoutMs / 1000))] }).length >
    SSM_COMMAND_LIMIT
  ) {
    const directory = `/var/lib/xcsh-csd-command-${randomUUID()}`;
    await invokeSsm(config, deps, `python3 - <<'PY'\nimport os\nos.mkdir('${directory}',0o700)\nPY`);
    try {
      await installWorkerFile(config, deps, `${directory}/command.sh`, script);
      return await invokeSsm(config, deps, `/bin/sh '${directory}/command.sh'`, { expectResult });
    } finally {
      await invokeSsm(
        config,
        { ...deps, signal: undefined },
        `python3 - <<'PY'\nimport os,stat\np='${directory}';fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);s=os.fstat(fd)\nif s.st_uid!=0 or stat.S_IMODE(s.st_mode)!=0o700: raise RuntimeError('unsafe command workspace')\ntry: os.unlink('command.sh',dir_fd=fd)\nexcept FileNotFoundError: pass\nos.close(fd);os.rmdir(p)\nPY`,
      );
    }
  }
  const parameters = {
    commands: [script],
    executionTimeout: [String(Math.ceil(deps.commandTimeoutMs / 1000))],
  };
  const send = parseJson(
    await command(
      deps,
      ssmArgs(
        config,
        'send-command',
        '--instance-ids',
        config.workerInstance,
        '--document-name',
        'AWS-RunShellScript',
        '--parameters',
        assertSsmParameters(parameters),
      ),
    ),
    'SSM_INVALID_JSON',
  );
  const commandId = send.Command?.CommandId;
  if (!commandId) throw new ControllerError('SSM did not return a command ID', 'SSM_FAILED');
  const deadline = deps.nowMs() + deps.commandTimeoutMs;
  let invocation;
  do {
    try {
      invocation = parseJson(
        await command(
          deps,
          ssmArgs(config, 'get-command-invocation', '--command-id', commandId, '--instance-id', config.workerInstance),
        ),
        'SSM_INVALID_JSON',
      );
    } catch (error) {
      if (error.code !== 'EXTERNAL_COMMAND_FAILED') throw error;
    }
    if (invocation && ['Success', 'Failed', 'TimedOut', 'Cancelled', 'Cancelling'].includes(invocation.Status)) break;
    await sleep(deps, Math.min(config.timings.pollMs || 1_000, 5_000));
  } while (deps.nowMs() < deadline);
  if (
    invocation?.Status !== 'Success' ||
    invocation.ResponseCode !== 0 ||
    invocation.StandardOutputUrl ||
    invocation.StandardErrorUrl
  )
    throw new ControllerError(
      `worker SSM command did not complete successfully inline${String(invocation?.StandardErrorContent || '').match(/RuntimeError: (probe entry failed: [^\r\n]{1,240})/)?.[1] ? ': ' + String(invocation.StandardErrorContent).match(/RuntimeError: (probe entry failed: [^\r\n]{1,240})/)[1] : ''}`,
      'SSM_FAILED',
    );
  if (!expectResult) return invocation;
  const output = String(invocation.StandardOutputContent || '');
  const lines = output.split('\n').filter((line) => line.startsWith('XCSH_RESULT '));
  if (lines.length !== 1 || output.length >= 24_000)
    throw new ControllerError('worker SSM output was missing, ambiguous, or truncated', 'SSM_OUTPUT_INVALID');
  return parseJson(lines[0].slice('XCSH_RESULT '.length), 'SSM_OUTPUT_INVALID');
}

export async function prepareWorker(config, deps, runId = deps.randomUUID(), originalWorker = null) {
  const { root } = workerIdentity(config, {
    runId,
    root: `/tmp/xcsh-csd-${runId}`,
  });
  const archive = await gzipBuffer(workerArchiveEntries(await workerSources(deps)));
  const sha256 = createHash('sha256').update(archive).digest('hex');
  const identity = workerIdentity(config, { runId, root });
  if (!config.reservationWorker) {
    await canaryReservationRecovery(
      { ...config, recoveryOriginalWorker: originalWorker },
      deps,
      identity,
      'initialize',
    );
  }
  await invokeSsm(config, deps, `/usr/bin/python3 '/var/lib/xcsh-csd-recovery/${runId}/helper.py' prepare`);
  const archivePath = `/var/lib/xcsh-csd-recovery/${runId}/sources.gz`;
  await installWorkerFile(config, deps, archivePath, archive.toString('binary'), 'root', true);
  const extraction = `set -eu;python3 - '${root}' '${archivePath}' '${sha256}' <<'PY'
import gzip,hashlib,json,os,pathlib,stat,sys
root=pathlib.Path(sys.argv[1]);journal=pathlib.Path('/var/lib/xcsh-csd-recovery')/root.name[9:]/'lifecycle.json'
fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);s=os.fstat(fd)
v=json.loads(journal.read_text())
if s.st_uid!=0 or stat.S_IMODE(s.st_mode)!=0o755 or v.get('root_inode')!=[s.st_dev,s.st_ino]: raise RuntimeError('worker preparation inode changed')
a=os.open(sys.argv[2],os.O_RDONLY|os.O_NOFOLLOW)
with os.fdopen(a,'rb') as f: archive=f.read()
if hashlib.sha256(archive).hexdigest()!=sys.argv[3]: raise RuntimeError('source digest mismatch')
data=gzip.decompress(archive).decode();i=0
while i<len(data):
 c=data.find(':',i);n=int(data[i:c]);name=data[c+1:c+1+n];i=c+1+n;c=data.find(':',i);size=int(data[i:c]);body=data[c+1:c+1+size];i=c+1+size
 if name not in ('csd-config.mjs','csd-scenarios.mjs','csd-runner.mjs'): raise RuntimeError('unexpected source name')
 out=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644,dir_fd=fd)
 with os.fdopen(out,'w') as f: f.write(body);f.flush();os.fchmod(f.fileno(),0o644);os.fsync(f.fileno())
os.fsync(fd);os.close(fd)
PY`;
  await invokeSsm(config, deps, extraction);
  return { ...workerIdentity(config, { runId, root }), sha256 };
}

const WORKER_CLEANUP_SCRIPT = `set -eu
python3 - "$1" "$2" <<'PY'
import json,os,re,shutil,sys,pathlib,stat
${WORKER_MUTEX_PROTOCOL}
${WORKER_FILESYSTEM_PROTOCOL}
mutex=reservation_mutex(pathlib.Path('/var/lib/xcsh-csd-reservation'),'csd-continuous.service')
root=sys.argv[1]
prefix=('--user-data-dir='+root+'/probe-').encode()
def scan():
    count=0
    with os.scandir('/proc') as entries:
        for entry in entries:
            if not entry.name.isdecimal(): continue
            count+=1
            if count>8192: raise RuntimeError('process scan limit')
            try:
                with open('/proc/'+entry.name+'/cmdline','rb') as cmd:
                    data=cmd.read(65537)
            except FileNotFoundError: continue
            if len(data)>65536: raise RuntimeError('process argv limit')
            for arg in data.split(b'\\0'):
                if arg.startswith(prefix) and arg.endswith(b'/profile'):
                    if not re.fullmatch(b'--user-data-dir='+re.escape(root.encode())+b'/probe-[A-Za-z0-9-]+/profile',arg):
                        raise RuntimeError('ambiguous owned Chrome profile')
                    raise RuntimeError('owned Chrome profile remains active')
scan()
if sys.argv[2]!='scan':
    worker_quarantine(pathlib.Path(root).name[9:])
    scan()
    if os.path.lexists(root): raise RuntimeError('worker root remains')
PY`;

export async function cleanupWorker(config, deps, worker) {
  if (!worker) return { worker_artifacts_removed: true };
  try {
    const { root } = validatedWorker(config, worker);
    await invokeSsm(config, deps, `set -- '${root}' cleanup;${WORKER_CLEANUP_SCRIPT}`);
    return { worker_artifacts_removed: true };
  } catch {
    return { worker_artifacts_removed: false };
  }
}

export async function installWorkerFile(config, deps, path, body, owner = 'root', binary = false) {
  if (!['root', 'ubuntu'].includes(owner))
    throw new ControllerError('invalid worker file owner', 'WORKER_IDENTITY_INVALID');
  const encoded = Buffer.from(body, binary ? 'binary' : 'utf8').toString('base64');
  const stage = `/var/lib/xcsh-csd-install-${randomUUID()}`;
  const check = `import os,pathlib,stat,sys\np=pathlib.Path(sys.argv[1]);fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)\nfor part in p.parts[1:]:\n child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);s=os.fstat(child)\n if s.st_uid!=0 or (stat.S_IMODE(s.st_mode)&0o022 and not (part=='tmp' and s.st_mode & stat.S_ISVTX)): raise RuntimeError('unsafe privileged directory')\n os.close(fd);fd=child`;
  await invokeSsm(config, deps, `python3 - '${stage}' <<'PY'\nimport os\nos.mkdir('${stage}',0o700)\nPY`);
  try {
    for (let offset = 0; offset < encoded.length; offset += 1500)
      await invokeSsm(
        config,
        deps,
        `python3 - '${stage}' <<'PY'\n${check}\nf=os.open('payload',os.O_WRONLY|os.O_CREAT|os.O_APPEND|os.O_NOFOLLOW,0o600,dir_fd=fd);s=os.fstat(f)\nif not stat.S_ISREG(s.st_mode) or s.st_uid!=0 or s.st_nlink!=1: raise RuntimeError('unsafe staging file')\nos.write(f,b'${encoded.slice(offset, offset + 1500)}');os.fsync(f);os.close(f);os.close(fd)\nPY`,
      );
    const directory = dirname(path);
    const name = basename(path);
    await invokeSsm(
      config,
      deps,
      `python3 - '${directory}' <<'PY'\n${check}\nimport base64,json,pwd\np=pathlib.Path(sys.argv[1]);s=os.fstat(fd)\nif p.parent==pathlib.Path('/tmp') and p.name.startswith('xcsh-csd-'):\n run=p.name[9:];j=pathlib.Path('/var/lib/xcsh-csd-recovery')/run/'lifecycle.json';v=json.loads(j.read_text())\n if v.get('root_inode')!=[s.st_dev,s.st_ino] or stat.S_IMODE(s.st_mode)!=0o755: raise RuntimeError('worker install inode changed')\ntry:\n old=os.stat('${name}',dir_fd=fd,follow_symlinks=False)\n if not stat.S_ISREG(old.st_mode) or old.st_uid!=0 or old.st_nlink!=1: raise RuntimeError('unsafe destination file')\nexcept FileNotFoundError: pass\nf=os.open('${stage}/payload',os.O_RDONLY|os.O_NOFOLLOW)\nwith os.fdopen(f,'rb') as source: body=base64.b64decode(source.read(),validate=True)\nname='.${name}.${randomUUID()}.install'\nf=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o700,dir_fd=fd)\nwith os.fdopen(f,'wb') as out: out.write(body);out.flush();os.fchmod(out.fileno(),${owner === 'ubuntu' ? '0o755' : '0o700'});os.fsync(out.fileno())\nos.rename(name,'${name}',src_dir_fd=fd,dst_dir_fd=fd);os.fsync(fd);os.close(fd)\nPY`,
    );
  } finally {
    await invokeSsm(
      config,
      { ...deps, signal: undefined },
      `python3 - '${stage}' <<'PY'\n${check}\nos.unlink('payload',dir_fd=fd);os.close(fd);os.rmdir('${stage}')\nPY`,
    );
  }
}

async function reservationAction(config, deps, worker, action) {
  if (deps.reservation) return deps.reservation(action);
  const recoveryDeps = { ...deps, signal: undefined };
  const { runId } = validatedWorker(config, worker);
  if (action === 'arm') {
    const guard = renderReservation({
      runId,
      lifetimeSeconds: reservationLifetime(config.timings),
    });
    await installWorkerFile(config, recoveryDeps, `/var/lib/xcsh-csd-recovery/${runId}/reservation.py`, guard.script);
  }
  const path =
    action === 'arm'
      ? `/var/lib/xcsh-csd-recovery/${runId}/reservation.py`
      : `/var/lib/xcsh-csd-reservation/${runId}/guard.py`;
  return invokeSsm(config, recoveryDeps, `/usr/bin/python3 '${path}' '${action}'`, {
    expectResult: action !== 'cleanup',
  });
}

async function probeWorkspace(config, deps, worker, probeId, payload, remove = false) {
  const { root, runId } = validatedWorker(config, worker);
  await invokeSsm(
    config,
    { ...deps, signal: remove ? undefined : deps.signal },
    `python3 - <<'PY'
import json,os,pathlib,pwd,stat,shutil,tempfile
p=pathlib.Path('${root}');j=pathlib.Path('/var/lib/xcsh-csd-recovery/${runId}/lifecycle.json')
fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);s=os.fstat(fd);v=json.loads(j.read_text());u=pwd.getpwnam('ubuntu')
if s.st_uid!=0 or stat.S_IMODE(s.st_mode)!=0o755 or v.get('root_inode')!=[s.st_dev,s.st_ino]: raise RuntimeError('worker workspace inode changed')
name='probe-${probeId}';payload='${basename(payload)}';records=v.setdefault('probes',{})
if ${remove ? 'True' : 'False'}:
 for process in pathlib.Path('/proc').iterdir():
  if not process.name.isdecimal(): continue
  try: argv=(process/'cmdline').read_bytes().split(b'\\0')
  except FileNotFoundError: continue
  if any(arg.startswith(('--user-data-dir='+str(p)+'/'+name+'/').encode()) for arg in argv): raise RuntimeError('owned browser remains active')
 record=records.get(name)
 if not record: raise RuntimeError('probe inode authority unavailable')
 child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd);c=os.fstat(child)
 if c.st_uid!=u.pw_uid or stat.S_IMODE(c.st_mode)!=0o700 or record['inode']!=[c.st_dev,c.st_ino]: raise RuntimeError('probe inode changed')
 current=os.stat(name,dir_fd=fd,follow_symlinks=False)
 if [current.st_dev,current.st_ino]!=record['inode']: raise RuntimeError('probe pathname changed')
 os.close(child)
 if not shutil.rmtree.avoids_symlink_attacks: raise RuntimeError('descriptor cleanup unavailable')
 shutil.rmtree(name,dir_fd=fd)
 f=os.stat(payload,dir_fd=fd,follow_symlinks=False)
 if f.st_uid!=0 or not stat.S_ISREG(f.st_mode) or f.st_nlink!=1 or record['payload_inode']!=[f.st_dev,f.st_ino]: raise RuntimeError('probe payload changed')
 os.unlink(payload,dir_fd=fd);del records[name]
else:
 os.mkdir(name,0o700,dir_fd=fd);child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
 os.fchown(child,u.pw_uid,u.pw_gid);c=os.fstat(child);os.fsync(child);os.close(child)
 f=os.stat(payload,dir_fd=fd,follow_symlinks=False)
 if f.st_uid!=0 or not stat.S_ISREG(f.st_mode) or f.st_nlink!=1: raise RuntimeError('unsafe probe payload')
 records[name]={'inode':[c.st_dev,c.st_ino],'payload_inode':[f.st_dev,f.st_ino]}
os.fsync(fd);os.close(fd)
f,tmp=tempfile.mkstemp(prefix='.probe-',dir=j.parent);os.fchmod(f,0o700)
with os.fdopen(f,'w') as out: json.dump(v,out);out.flush();os.fsync(out.fileno())
os.replace(tmp,j);fd=os.open(j.parent,os.O_DIRECTORY|os.O_NOFOLLOW);os.fsync(fd);os.close(fd)
PY`,
  );
}

export async function runHeadedWorkerProbe(config, deps, headerId, worker) {
  const { root, runId } = validatedWorker(config, worker);
  if (config.fixtureTarget && (!config.fixtureTarget.startsWith('data:text/html,') || headerId !== null))
    throw new ControllerError('fixture target must be an isolated control data URL', 'CLI_ERROR');
  if (config.reservationWorker) await reservationAction(config, deps, config.reservationWorker, 'verify');
  const probeId = deps.randomUUID();
  const entry = `import { CdpClient, runDocumentProbe } from '${root}/csd-runner.mjs';
const body=await (await fetch('http://127.0.0.1:'+process.env.XCSH_PROBE_PORT+'/json/version')).json();
const cdp=await CdpClient.connect(body.webSocketDebuggerUrl,${Number(config.probeTimeoutMs)},WebSocket);
try{const args=await cdp.send('Browser.getBrowserCommandLine');const version=await cdp.send('Browser.getVersion');
if(args.arguments.some(a=>a.startsWith('--headless'))||!args.arguments.includes('--user-data-dir=${root}/probe-${probeId}/profile')||version.product.includes('Headless'))throw new Error('headed browser provenance invalid');
const result=${config.fixtureTarget ? `await (async()=>{const t=await cdp.send('Target.createTarget',{url:${JSON.stringify(config.fixtureTarget)}});await cdp.send('Target.closeTarget',{targetId:t.targetId});return {success:true,fixture_target:'data-url',cleanup:{target_closed:true}};})()` : `await runDocumentProbe(${JSON.stringify(probeOptions(config, headerId))},{cdp})`};
result._browser_evidence={arguments:args.arguments,product:version.product};console.log('XCSH_RESULT '+JSON.stringify(result));}finally{cdp.close();}`;
  const path = `${root}/headed-${probeId}.py`;
  await installWorkerFile(config, deps, path, renderHeadedProbe({ root, probeId, entry }), 'ubuntu');
  await probeWorkspace(config, deps, worker, probeId, path);
  const unit = `xcsh-csd-probe-${runId}-${probeId}.service`;
  try {
    return await invokeSsm(
      config,
      deps,
      // Ubuntu's installed Chrome profile permits user namespaces while Chrome retains its sandbox.
      `systemd-run --quiet --wait --pipe --collect --unit='${unit}' --property=User=ubuntu --property=AppArmorProfile=chrome --property=KillMode=control-group --property=RuntimeMaxSec=180s /usr/bin/python3 '${path}'`,
      { expectResult: true },
    );
  } finally {
    await invokeSsm(
      config,
      { ...deps, signal: undefined },
      `set -eu;systemctl stop '${unit}' || [ "$(systemctl show '${unit}' -p LoadState --value)" = not-found ]`,
    );
    await probeWorkspace(config, deps, worker, probeId, path, true);
  }
}

export async function runWorkerProbe(config, deps, headerId = null, worker = null) {
  if (config.browserMode === 'headed-xvfb') return runHeadedWorkerProbe(config, deps, headerId, worker);
  const owned = worker ? validatedWorker(config, worker) : await prepareWorker(config, deps);
  const probeId = deps.randomUUID();
  const probeRoot = `${owned.root}/probe-${probeId}`;
  const entry = Buffer.from(
    `import { CdpClient, runDocumentProbe } from '${owned.root}/csd-runner.mjs';\nconst version=await fetch('http://127.0.0.1:9222/json/version');const body=await version.json();const cdp=await CdpClient.connect(body.webSocketDebuggerUrl,${Number(config.probeTimeoutMs)},WebSocket);try{const result=await runDocumentProbe(${JSON.stringify(probeOptions(config, headerId))},{cdp});console.log('XCSH_RESULT '+JSON.stringify(result));}finally{cdp.close();}`,
  ).toString('base64');
  const userScript = `#!/bin/sh
set -eu;probe='${probeRoot}';profile="$probe/profile";pidfile="$probe/chrome.pid";spawn="$probe/chrome-launch";pid='';pgid='';launcher_pid=$$;launcher_pgid=$(ps -o pgid= -p $$|tr -d ' ');alive(){ kill -0 "$pid" 2>/dev/null||kill -0 -- "-$pgid" 2>/dev/null;};cleanup(){ rc=0;if [ -s "$pidfile" ];then read pid pgid <"$pidfile"||rc=1;fi;case "$pid:$pgid" in :*|*:|*[!0-9:]*|0:*|*:0) rc=1;;esac;if [ "$rc" -eq 0 ]&&{ [ "$pid" = "$launcher_pid" ]||[ "$pgid" = "$launcher_pgid" ];};then rc=1;fi;if [ "$rc" -eq 0 ];then kill -TERM -- "-$pgid" 2>/dev/null||kill -TERM "$pid" 2>/dev/null||true;i=0;while alive&&[ "$i" -lt 5 ];do i=$((i+1));sleep 1;done;if alive;then kill -KILL -- "-$pgid" 2>/dev/null||kill -KILL "$pid" 2>/dev/null||true;i=0;while alive&&[ "$i" -lt 5 ];do i=$((i+1));sleep 1;done;fi;if alive;then echo "chrome cleanup timeout pid=$pid pgid=$pgid" >&2;rc=1;fi;else echo "unsafe chrome identity pid=$pid pgid=$pgid launcher=$launcher_pid/$launcher_pgid" >&2;fi;for child in "$probe"/* "$probe"/.[!.]* "$probe"/..?*;do [ ! -e "$child" ]&&[ ! -L "$child" ]||rm -rf -- "$child"||rc=1;done;return "$rc";};trap 'cleanup||true' EXIT INT TERM;umask 077;mkdir -p "$profile";printf %s '${entry}'|base64 -d >"$probe/entry.mjs";node_bin='';for c in /opt/node/bin/node node;do if [ -x "$c" ];then node_bin="$c";break;fi;if command -v "$c" >/dev/null 2>&1;then node_bin=$(command -v "$c");break;fi;done;[ -n "$node_bin" ]||exit 36;chrome='';for c in /opt/chrome/chrome google-chrome-stable google-chrome chromium chromium-browser;do if command -v "$c" >/dev/null 2>&1;then chrome=$(command -v "$c");break;fi;done;[ -n "$chrome" ]||exit 31;[ -x /usr/bin/setsid ]||exit 37;cat >"$spawn" <<'SH'
#!/bin/sh
set -eu;pidfile=$1;shift;pid=$$;pgid=$(ps -o pgid= -p $$|tr -d ' ');printf '%s %s\\n' "$pid" "$pgid" >"$pidfile";exec "$@"
SH
chmod 700 "$spawn";/usr/bin/setsid --fork "$spawn" "$pidfile" "$chrome" --headless=new --no-first-run --no-default-browser-check --remote-debugging-address=127.0.0.1 --remote-debugging-port=9222 --user-data-dir="$profile" about:blank >/dev/null 2>&1;i=0;while [ ! -s "$pidfile" ];do i=$((i+1));[ "$i" -lt 10 ]||exit 38;sleep 1;done;read pid pgid <"$pidfile";case "$pid:$pgid" in :*|*:|*[!0-9:]*|0:*|*:0) exit 39;;esac;if [ "$pid" = "$launcher_pid" ]||[ "$pid" = "$launcher_pgid" ]||[ "$pgid" = "$launcher_pid" ]||[ "$pgid" = "$launcher_pgid" ];then exit 39;fi;i=0;until "$node_bin" -e "fetch('http://127.0.0.1:9222/json/version').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))";do i=$((i+1));[ "$i" -lt 60 ]||exit 32;sleep 1;done;"$node_bin" "$probe/entry.mjs";cleanup||exit 34;trap - EXIT INT TERM`;
  const launcher = `${owned.root}/.launch-${probeId}`;
  let result;
  let failure;
  try {
    await installWorkerFile(config, deps, launcher, userScript, 'ubuntu');
    await probeWorkspace(config, deps, owned, probeId, launcher);
    const script = `set -eu;sudo -u ubuntu -H '${launcher}'`;
    result = await invokeSsm(config, deps, script, { expectResult: true });
  } catch (error) {
    failure = error;
  } finally {
    await probeWorkspace(config, deps, owned, probeId, launcher, true);
  }
  if (!worker) {
    const cleanup = await cleanupWorker(config, { ...deps, signal: undefined }, owned);
    if (!cleanup.worker_artifacts_removed)
      throw new ControllerError('self-owned worker root cleanup failed', 'RECOVERY_FAILED', 5);
  }
  if (failure) throw failure;
  return result;
}

async function browserProbe(config, deps, headerId = null, location = 'workstation', worker = null) {
  if (config.placement === 'worker') location = 'worker';
  let result;
  if (deps.probe) result = await deps.probe({ config, headerId, location, worker });
  else if (location === 'worker')
    result = deps.workerProbe
      ? await deps.workerProbe({
          config,
          headerId,
          options: probeOptions(config, headerId),
          worker,
        })
      : await runWorkerProbe(config, deps, headerId, worker);
  if (result) {
    if (config.browserMode === 'headed-xvfb') {
      const evidence = result.browser_provenance;
      if (
        evidence?.mode !== 'headed-xvfb' ||
        evidence.placement !== 'worker' ||
        !evidence.process_arguments_verified ||
        !evidence.browser_arguments_verified ||
        !evidence.owned_display_verified
      )
        throw new ControllerError('headed browser provenance cannot be verified', 'INVALID_TEST');
      config.browserProvenance = evidence;
    }
    return result;
  }
  const cdp = deps.cdp || (await connectCdp(config, deps));
  try {
    return await runDocumentProbe(probeOptions(config, headerId), {
      cdp,
      signal: deps.signal,
    });
  } finally {
    if (!deps.cdp) cdp.close();
  }
}

const MAX_HISTORY_PAGES = 20;
const HISTORY_PAGE_SIZE = 500;

async function pollAlerts(config, deps, expected) {
  if (deps.alertSource) return deps.alertSource(expected);
  const headers = { Authorization: `APIToken ${config.f5ApiToken}` };
  const base = `${REVIEWED.f5ApiOrigin}/api/data/namespaces/${encodeURIComponent(config.namespace)}/alerts`;
  const get = async (url) => {
    const response = await deps.fetch(url, { headers, signal: deps.signal });
    if (!response.ok) throw new ControllerError('alert telemetry request failed', 'TELEMETRY_GAP');
    try {
      return await response.json();
    } catch {
      throw new ControllerError('alert telemetry returned invalid JSON', 'TELEMETRY_GAP');
    }
  };
  const current = await Promise.all(
    ['', 'inactive', 'silenced', 'inhibited', 'unprocessed'].map(async (state) => {
      const url = new URL(base);
      if (state) url.searchParams.set(state, 'true');
      const payload = await get(url.toString());
      if (payload === null || typeof payload !== 'object' || (!Array.isArray(payload) && !('data' in payload)))
        throw new ControllerError('invalid current alert view', 'TELEMETRY_GAP');
      if (!Array.isArray(payload) && typeof payload.data === 'string') {
        let parsed;
        try {
          parsed = JSON.parse(payload.data);
        } catch {
          throw new ControllerError('invalid current alert data', 'TELEMETRY_GAP');
        }
        if (!parsed || typeof parsed !== 'object')
          throw new ControllerError('invalid current alert data', 'TELEMETRY_GAP');
      } else if (!Array.isArray(payload) && (!payload.data || typeof payload.data !== 'object')) {
        throw new ControllerError('invalid current alert data', 'TELEMETRY_GAP');
      }
      return payload;
    }),
  );
  const historyUrl = new URL(`${base}/history`);
  const start = new Date(expected.windowStart);
  const end = new Date(expected.windowEnd);
  if (!Number.isFinite(start.getTime()) || !Number.isFinite(end.getTime()) || start > end)
    throw new ControllerError('invalid alert history window', 'TELEMETRY_GAP');
  historyUrl.searchParams.set('start_time', start.toISOString());
  historyUrl.searchParams.set('end_time', end.toISOString());
  const history = [];
  const seenCursors = new Set();
  let cursor = null;
  let total = null;
  for (let page = 0; page < MAX_HISTORY_PAGES; page += 1) {
    const url = cursor ? new URL(`${base}/history/scroll`) : new URL(historyUrl);
    if (cursor) url.searchParams.set('scroll_id', cursor);
    const payload = await get(url.toString());
    if (
      !payload ||
      typeof payload !== 'object' ||
      Array.isArray(payload) ||
      !Array.isArray(payload.alerts) ||
      !/^(0|[1-9]\d*)$/.test(payload.total_hits) ||
      !Number.isSafeInteger(Number(payload.total_hits)) ||
      Number(payload.total_hits) > MAX_HISTORY_PAGES * HISTORY_PAGE_SIZE ||
      payload.alerts.length > HISTORY_PAGE_SIZE ||
      typeof payload.scroll_id !== 'string'
    )
      throw new ControllerError('invalid alert history page', 'TELEMETRY_GAP');
    const hits = Number(payload.total_hits);
    if (total === null) total = hits;
    if (hits !== total || history.length + payload.alerts.length > total)
      throw new ControllerError('inconsistent alert history total', 'TELEMETRY_GAP');
    for (const record of payload.alerts) {
      let parsed;
      try {
        parsed = typeof record === 'string' ? JSON.parse(record) : record;
      } catch {
        throw new ControllerError('invalid alert history record', 'TELEMETRY_GAP');
      }
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed))
        throw new ControllerError('invalid alert history record', 'TELEMETRY_GAP');
      history.push(parsed);
    }
    if (history.length === total) return { current, history };
    if (!payload.scroll_id || seenCursors.has(payload.scroll_id) || !payload.alerts.length)
      throw new ControllerError('incomplete alert history pagination', 'TELEMETRY_GAP');
    seenCursors.add(payload.scroll_id);
    cursor = payload.scroll_id;
  }
  throw new ControllerError('alert history page limit exceeded', 'TELEMETRY_GAP');
}

function alertViews(payload) {
  if (payload && !Array.isArray(payload) && ('current' in payload || 'history' in payload))
    return { current: payload.current || [], history: payload.history || [] };
  if (!Array.isArray(payload)) return { current: payload ? [payload] : [], history: [] };
  return { current: payload[0] || [], history: payload.slice(1) };
}

function alertExpected(config, headerId, windowStart, windowEnd) {
  return {
    namespace: config.namespace,
    origin: new URL(config.target).origin,
    path: PAYMENT_PATH,
    headerId,
    windowStart,
    windowEnd,
  };
}

async function pollCandidateAlerts(config, deps, windowStart, windowEnd) {
  if (!deps.alertSource)
    return [await pollAlerts(config, deps, alertExpected(config, HEADER_IDS[0], windowStart, windowEnd))];
  return Promise.all(
    HEADER_IDS.map((headerId) => deps.alertSource(alertExpected(config, headerId, windowStart, windowEnd))),
  );
}

function correlateCandidateAlerts(payloads, config, windowStart, windowEnd, knownFiring = null) {
  const matches = HEADER_IDS.flatMap((headerId) =>
    payloads.flatMap((payload) =>
      correlateAlertViews(alertViews(payload), alertExpected(config, headerId, windowStart, windowEnd), {
        allowPriorResolution: knownFiring !== null,
      }),
    ),
  );
  const filtered = knownFiring
    ? matches.filter((alert) => alert.state === 'firing' || knownFiring.has(alertIdentity(alert)))
    : matches;
  return [
    ...new Map(
      filtered.map((alert) => [`${alertIdentity(alert)}|${alert.state}|${alert.ends_at || ''}`, alert]),
    ).values(),
  ];
}

function correlateBoundedPayloads(payloads, expected) {
  const alerts = payloads.flatMap((payload) => {
    const matches = correlateAlertViews(alertViews(payload), expected);
    if (
      matches.some((item) => item.state === 'firing' && Date.parse(item.starts_at) < Date.parse(expected.windowStart))
    )
      throw new ControllerError('matching current alert predates the campaign window', 'INVALID_TEST');
    return matches;
  });
  return [...new Map(alerts.map((alert) => [alertIdentity(alert), alert])).values()];
}

function alertIdentity(alert) {
  return [
    alert.alert_name,
    alert.display_name || '',
    alert.header_id,
    alert.starts_at,
    alert.path,
    alert.namespace,
  ].join('|');
}

function observeAlertLifecycle(knownFiring, alerts) {
  let observedFiring = false;
  for (const alert of alerts) {
    const identity = alertIdentity(alert);
    if (alert.state === 'firing') {
      knownFiring.add(identity);
      observedFiring = true;
    } else if (alert.state === 'resolved') knownFiring.delete(identity);
  }
  return observedFiring;
}
const findStates = (value, states = []) => {
  if (Array.isArray(value))
    value.forEach((item) => {
      findStates(item, states);
    });
  else if (value && typeof value === 'object')
    for (const [key, child] of Object.entries(value)) {
      if (typeof child === 'string' && /state|status/i.test(key)) states.push(child);
      else findStates(child, states);
    }
  return states;
};
async function readiness(config, deps, outputs) {
  if (deps.readiness) return deps.readiness(config, outputs);
  const headers = { Authorization: `APIToken ${config.f5ApiToken}` };
  const lbUrl = `${REVIEWED.f5ApiOrigin}/api/config/namespaces/${REVIEWED.namespace}/http_loadbalancers/${REVIEWED.lbName}`;
  const [lb, targetHealth, payment, application] = await Promise.all([
    deps.fetch(lbUrl, { headers, signal: deps.signal }),
    command(
      deps,
      [
        'aws',
        'elbv2',
        'describe-target-health',
        '--target-group-arn',
        outputs.page_tamper_target_group_arn.value,
        ...awsBase(config),
      ],
      { signal: deps.signal },
    ),
    deps.fetch(config.target, { signal: deps.signal }),
    deps.fetch(`${REVIEWED.targetOrigin}/`, { signal: deps.signal }),
  ]);
  if (!lb.ok) throw new ControllerError('load balancer readiness request failed', 'READINESS_FAILED');
  const states = findStates(await lb.json());
  const health = parseJson(targetHealth, 'AWS_INVALID_JSON').TargetHealthDescriptions || [];
  return {
    payment_health: payment.status === 200,
    application_health: application.status === 200,
    lb_ready: states.includes('VIRTUAL_HOST_READY'),
    certificate_valid: states.some((state) => ['CertificateValid', 'AutoCertRenewing'].includes(state)),
    page_tamper_targets_healthy: health.length > 0 && health.every((item) => item.TargetHealth?.State === 'healthy'),
  };
}
const safetyPasses = (value) => Object.values(value).every(Boolean);
async function verifyCleanup(config, deps, worker = null, finalizeWorker = true) {
  if (deps.cleanup) return deps.cleanup(config, worker);
  const local = { browser_artifacts_removed: true };
  if (!worker) return { ...local, worker_artifacts_removed: true };
  if (finalizeWorker) return { ...local, ...(await cleanupWorker(config, deps, worker)) };
  try {
    const { root } = validatedWorker(config, worker);
    await invokeSsm(
      config,
      deps,
      `set -eu;[ -d '${root}' ];! find '${root}' -maxdepth 1 -type d -name 'probe-*' -print -quit|grep -q .;set -- '${root}' scan;${WORKER_CLEANUP_SCRIPT}`,
    );
    return { ...local, worker_artifacts_removed: true };
  } catch {
    return { ...local, worker_artifacts_removed: false };
  }
}
async function controlPair(config, deps, worker = null) {
  const workstation = await browserProbe(config, deps, null, 'workstation', worker);
  const remote = await browserProbe(config, deps, null, 'worker', worker);
  if (!validProbe(workstation) || !validProbe(remote))
    throw new ControllerError('control probe pair failed', 'INVALID_TEST');
  return { workstation, worker: remote };
}

async function runControlTraffic(config, deps, durationMs, worker = null) {
  const deadline = deps.nowMs() + durationMs;
  let completedPairs = 0;
  while (deps.nowMs() < deadline) {
    await controlPair(config, deps, worker);
    completedPairs++;
    await sleep(deps, Math.min(Math.max(1, config.timings.pollMs), Math.max(1, deadline - deps.nowMs())));
  }
  return completedPairs;
}

async function recover(config, deps, outputs, worker = null, finalizeWorker = true) {
  const recoveryDeps = { ...deps, signal: undefined };
  const controlPairs = await runControlTraffic(config, recoveryDeps, config.timings.recoveryMs, worker);
  const final = await controlPair(config, recoveryDeps, worker);
  const ready = await readiness(config, recoveryDeps, outputs);
  const cleanup = await verifyCleanup(config, recoveryDeps, worker, finalizeWorker);
  const drift = await noDrift(config, recoveryDeps);
  return {
    control_pairs: controlPairs,
    probes_valid: validProbe(final.workstation) && validProbe(final.worker),
    readiness: ready,
    cleanup,
    no_drift: drift,
    success:
      validProbe(final.workstation) &&
      validProbe(final.worker) &&
      safetyPasses(ready) &&
      safetyPasses(cleanup) &&
      drift.no_drift,
  };
}
async function sleep(deps, ms) {
  if (ms > 0) await deps.sleep(ms, deps.signal);
}

// Root-private recovery evidence survives removal of the reservation authority.
export function renderCanaryRecoveryHelper(
  identity,
  { service = 'csd-continuous.service', timer = 'csd-continuous.timer', fixture = false, originalWorker = null } = {},
) {
  if (
    !SAFE_WORKER_RUN_ID.test(identity.runId) ||
    identity.root !== `/tmp/xcsh-csd-${identity.runId}` ||
    (!fixture && (service !== 'csd-continuous.service' || timer !== 'csd-continuous.timer')) ||
    (fixture &&
      (!/^xcsh-csd-fixture-[a-z0-9-]+\.service$/.test(service) || !/^xcsh-csd-fixture-[a-z0-9-]+\.timer$/.test(timer)))
  )
    throw new ControllerError('invalid recovery helper identity', 'WORKER_IDENTITY_INVALID');
  return `#!/usr/bin/python3
import json,os,pathlib,stat,subprocess,sys,tempfile
identity=${JSON.stringify(identity)};mode=sys.argv[1];run=identity['runId']
service=${JSON.stringify(service)};timer=${JSON.stringify(timer)}
root=pathlib.Path('/var/lib/xcsh-csd-reservation')/run
owner=root.parent/(service+'.owner')
parent=pathlib.Path('/var/lib/xcsh-csd-recovery');directory=parent/run;path=directory/'verified.json'
def private(p,d=False):
 s=p.lstat()
 if s.st_uid!=0 or stat.S_IMODE(s.st_mode)!=0o700 or not (stat.S_ISDIR(s.st_mode) if d else stat.S_ISREG(s.st_mode)) or (not d and s.st_nlink!=1): raise RuntimeError('non-private recovery authority')
${WORKER_MUTEX_PROTOCOL}
${WORKER_FILESYSTEM_PROTOCOL}
os.close(canonical_directory(root.parent,True))
os.close(canonical_directory(parent,True))
os.close(canonical_directory(directory,True))
journal=directory/'lifecycle.json'
def save(value):
 for p in (parent,directory): p.mkdir(mode=0o700,exist_ok=True);private(p,True)
 fd,temporary=tempfile.mkstemp(prefix='.verified-',dir=directory);os.fchmod(fd,0o700)
 with os.fdopen(fd,'w') as out: json.dump(value,out);out.flush();os.fsync(out.fileno())
 os.replace(temporary,path)
 fd=os.open(directory,os.O_DIRECTORY);os.fsync(fd);os.close(fd)
def state(unit):
 result=subprocess.run(['systemctl','show',unit,'--property=LoadState,ActiveState,UnitFileState,Type,RemainAfterExit,Triggers'],capture_output=True,text=True)
 values=dict(line.split('=',1) for line in result.stdout.splitlines() if '=' in line)
 if not values: raise RuntimeError('systemd observation unavailable')
 return values
def lifecycle_save(value):
 fd,temporary=tempfile.mkstemp(prefix='.lifecycle-',dir=directory);os.fchmod(fd,0o700)
 with os.fdopen(fd,'w') as out: json.dump(value,out);out.flush();os.fsync(out.fileno())
 os.replace(temporary,journal)
 fd=os.open(directory,os.O_DIRECTORY|os.O_NOFOLLOW);os.fsync(fd);os.close(fd)
def lifecycle_load():
 private(journal);value=json.loads(journal.read_text())
 if value.get('contract')!='xcsh-csd-prearm-v1' or value.get('worker_identity')!=identity or value.get('service')!=service or value.get('timer')!=timer: raise RuntimeError('prearm identity mismatch')
 return value
def absent_authority():
 if os.path.lexists(root) or os.path.lexists(owner): raise RuntimeError('reservation authority exists')
 name='xcsh-csd-restore-'+run
 for suffix in ('service','timer'):
  unit=name+'.'+suffix
  if os.path.lexists(pathlib.Path('/etc/systemd/system',unit)) or state(unit).get('LoadState')!='not-found': raise RuntimeError('reservation unit exists')
 if os.path.lexists(pathlib.Path('/run/systemd/system',name+'.timer.d')): raise RuntimeError('reservation override exists')
 units=subprocess.run(['systemctl','list-units','--all','--plain','--no-legend','xcsh-csd-probe-'+run+'-*'],capture_output=True,text=True,check=True)
 if units.stdout.strip(): raise RuntimeError('run probe unit exists')
 for process in pathlib.Path('/proc').iterdir():
  if not process.name.isdecimal(): continue
  try: argv=(process/'cmdline').read_bytes().split(b'\\0')
  except FileNotFoundError: continue
  if any(identity['root'].encode() in arg for arg in argv): raise RuntimeError('run process exists')
if mode=='classify':
 mutex=reservation_mutex(root.parent,service)
 try:
  value=lifecycle_load()
  prearm=value.get('phase') in ('NOT_ARMED','PREARM_CLEANUP_INTENT','PREARM_CLEANED') and value.get('pause_intent') is False
  print('XCSH_RESULT '+json.dumps({'schema_version':1,'externally_verified':True,'worker_identity':identity,'prearm':prearm}))
 finally: os.close(mutex)
 sys.exit(0)
if mode in ('initialize','prepare','prearm'):
 mutex=reservation_mutex(root.parent,service)
 try:
  absent_authority()
  if mode=='initialize':
   if os.path.lexists(journal) or os.path.lexists(identity['root']): raise RuntimeError('prearm run already exists')
   value={'contract':'xcsh-csd-prearm-v1','worker_identity':identity,'service':service,'timer':timer,'phase':'NOT_ARMED','pause_intent':False}
   original_identity=json.loads(${JSON.stringify(JSON.stringify(originalWorker))})
   if original_identity:
    old=original_identity['runId']
    if old==run or original_identity['root']!='/tmp/xcsh-csd-'+old: raise RuntimeError('recovery identity must be fresh')
    original_journal,original_value=worker_authority(old)
    if original_value.get('worker_identity')!=original_identity or original_value.get('cleanup_intent') is not True or os.path.lexists(original_identity['root']): raise RuntimeError('original cleanup authority unavailable')
    value['recovery_original']={'worker_identity':original_identity,'root_inode':original_value.get('root_inode'),'cleanup_intent':True}
   lifecycle_save(value)
  else:
   value=lifecycle_load()
   if value.get('phase') not in ('NOT_ARMED','PREARM_CLEANUP_INTENT','PREARM_CLEANED') or value.get('pause_intent') is not False: raise RuntimeError('prearm authority unavailable; original restoration required')
   if mode=='prepare':
    if value['phase']!='NOT_ARMED' or os.path.lexists(identity['root']): raise RuntimeError('worker root already exists')
    value['prepare_intent']=True;lifecycle_save(value)
    os.mkdir(identity['root'],0o755);fd=os.open(identity['root'],os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);os.fchmod(fd,0o755);s=os.fstat(fd);os.fsync(fd);os.close(fd)
    fd=os.open('/tmp',os.O_DIRECTORY|os.O_NOFOLLOW);os.fsync(fd);os.close(fd)
    value['root_inode']=[s.st_dev,s.st_ino];lifecycle_save(value)
   else:
    value['phase']='PREARM_CLEANUP_INTENT';lifecycle_save(value)
    worker_quarantine(run)
    value=lifecycle_load()
    absent_authority()
    value['phase']='PREARM_CLEANED';lifecycle_save(value)
  print('XCSH_RESULT '+json.dumps({'schema_version':1,'externally_verified':True,'worker_identity':identity,'prearm':True,'restoration':{'restored':False,'required':False},'worker_artifacts_removed':mode=='prearm','reservation_artifacts_removed':mode=='prearm'}))
 finally: os.close(mutex)
 sys.exit(0)
def validate(original,complete=False):
 if original.get('run_id')!=run or original.get('service')!=service or original.get('timer')!=timer: raise RuntimeError('original identity mismatch')
 if original.get('phase') not in ('draining','prepared','service_intent','service_resumed','timer_intent','resumed','complete') or (complete and original['phase']!='complete'): raise RuntimeError('original phase mismatch')
 for unit in (service,timer):
  prior=original.get(unit,{})
  if prior.get('ActiveState') not in ('active','inactive') or prior.get('UnitFileState') not in ('enabled','disabled','static'): raise RuntimeError('invalid original state')
 if not original[service].get('Type') or original[service].get('RemainAfterExit') not in ('yes','no') or service not in original[timer].get('Triggers','').split(): raise RuntimeError('invalid original dispatch policy')
def verify(original):
 validate(original,True)
 for unit in (service,timer):
  prior=original[unit];actual=state(unit)
  if actual.get('LoadState')!='loaded' or actual.get('UnitFileState')!=prior['UnitFileState']: raise RuntimeError('dispatch policy changed')
  allowed={prior['ActiveState']}
  if unit==timer:
   if service not in actual.get('Triggers','').split(): raise RuntimeError('timer target changed')
  else:
   if any(actual.get(k)!=prior[k] for k in ('Type','RemainAfterExit')): raise RuntimeError('service semantics changed')
   if original[timer]['ActiveState']=='active': allowed={'active','activating','inactive'}
   elif prior['ActiveState']=='active' and prior['Type']=='oneshot' and prior['RemainAfterExit']=='no': allowed={'inactive'}
  if actual.get('ActiveState') not in allowed: raise RuntimeError('original dispatch state unverified')
def probe_cleanup():
 if os.path.lexists(identity['root']): raise RuntimeError('worker root remains')
 prefix=('--user-data-dir='+identity['root']+'/probe-').encode()
 for process in pathlib.Path('/proc').iterdir():
  if not process.name.isdecimal(): continue
  try: argv=(process/'cmdline').read_bytes().split(b'\\0')
  except FileNotFoundError: continue
  if any(arg.startswith(prefix) for arg in argv): raise RuntimeError('owned browser remains')
def external(p):
 private(p);e=json.loads(p.read_text())
 if e.get('contract')!='xcsh-csd-restore-evidence-v1' or e.get('externally_verified') is not True: raise RuntimeError('external evidence unavailable')
 original=e.get('reservation',{});verify(original);probe_cleanup();return original
record=None
if os.path.lexists(path):
 private(parent,True);private(directory,True);private(path)
 record=json.loads(path.read_text())
 if record.get('schema_version')!=1 or record.get('externally_verified') is not True or record.get('worker_identity')!=identity or record.get('restoration')!={'restored':True,'original_states_preserved':True}: raise RuntimeError('recovery evidence identity mismatch')
if os.path.lexists(root):
 private(root.parent,True);private(root,True);private(root/'guard.py');private(owner)
 if owner.read_text()!=run: raise RuntimeError('reservation ownership mismatch')
 if mode=='restore':
  snapshot=root/'state.json'
  if os.path.lexists(snapshot):
   private(snapshot);original=json.loads(snapshot.read_text());validate(original)
  else:
   original=external(root/'restore-evidence.json')
   guard=state('xcsh-csd-restore-'+run+'.timer')
   if guard.get('LoadState')!='not-found' and (guard.get('ActiveState')!='inactive' or guard.get('UnitFileState')!='disabled'): raise RuntimeError('guard is not disarmed')
  result=subprocess.run(['/usr/bin/python3',str(root/'guard.py'),'restore'],capture_output=True,text=True,check=True)
  reports=[json.loads(line[len('XCSH_RESULT '):]) for line in result.stdout.splitlines() if line.startswith('XCSH_RESULT ')]
  if len(reports)!=1 or reports[0].get('restored') is not True or reports[0].get('original_states_preserved') is not True: raise RuntimeError('guard restoration unverified')
  if os.path.lexists(snapshot):
   private(snapshot);completed=json.loads(snapshot.read_text());verify(completed)
   if any(completed.get(k)!=original.get(k) for k in ('run_id','service','timer',service,timer)): raise RuntimeError('original snapshot changed')
   original=completed
  verify(original)
  record={'schema_version':1,'externally_verified':True,'worker_identity':identity,'original':original,'restoration':{'restored':True,'original_states_preserved':True}}
  save(record)
elif record is None: raise RuntimeError('durable restoration authority unavailable')
if not os.path.lexists(root) and os.path.lexists(owner): raise RuntimeError('reservation owner remains without original authority')
if record is None: raise RuntimeError('verified restoration evidence unavailable')
verify(record['original'])
if not os.path.lexists(root):
 probe_cleanup()
 name='xcsh-csd-restore-'+run
 for suffix in ('service','timer'):
  if os.path.lexists(pathlib.Path('/etc/systemd/system',name+'.'+suffix)) or state(name+'.'+suffix).get('LoadState')!='not-found': raise RuntimeError('guard unit remains')
 if os.path.lexists(pathlib.Path('/run/systemd/system',name+'.timer.d')): raise RuntimeError('guard override remains')
if mode=='cleanup':
 probe_cleanup();record['worker_artifacts_removed']=True;save(record)
 if root.exists(): subprocess.run(['/usr/bin/python3',str(root/'guard.py'),'cleanup'],capture_output=True,text=True,check=True)
 name='xcsh-csd-restore-'+run
 if os.path.lexists(root) or os.path.lexists(owner): raise RuntimeError('reservation remains')
 for suffix in ('service','timer'):
  unit=name+'.'+suffix
  if os.path.lexists(pathlib.Path('/etc/systemd/system',unit)) or state(unit).get('LoadState')!='not-found': raise RuntimeError('guard unit remains')
 if os.path.lexists(pathlib.Path('/run/systemd/system',name+'.timer.d')): raise RuntimeError('guard override remains')
 verify(record['original']);probe_cleanup();record['reservation_artifacts_removed']=True;save(record)
elif mode!='restore': raise RuntimeError('invalid recovery action')
print('XCSH_RESULT '+json.dumps(record))
`;
}

async function canaryReservationRecovery(config, deps, worker, action) {
  const identity = validatedWorker(config, worker);
  if (deps.reservationRecovery) return deps.reservationRecovery(action, identity);
  const recoveryDeps = { ...deps, signal: undefined };
  const directory = `/var/lib/xcsh-csd-recovery/${identity.runId}`;
  const path = `${directory}/helper.py`;
  const check = `import os,pathlib,stat\n${WORKER_MUTEX_PROTOCOL}\nroot=pathlib.Path('${directory}')\nfor p in (root.parent,root):\n os.close(canonical_directory(p,True))\nfor p in (root/'helper.py',root/'helper.py.b64',root/'reservation.py',root/'reservation.py.b64'):\n if os.path.lexists(p):\n  s=p.lstat()\n  if s.st_uid!=0 or stat.S_IMODE(s.st_mode)!=0o700 or not stat.S_ISREG(s.st_mode) or s.st_nlink!=1: raise RuntimeError('unsafe recovery helper')`;
  await invokeSsm(config, recoveryDeps, `set -eu\n/usr/bin/python3 - <<'PY'\n${check}\nPY`);
  await installWorkerFile(
    config,
    recoveryDeps,
    path,
    renderCanaryRecoveryHelper(identity, { originalWorker: config.recoveryOriginalWorker || null }),
  );
  await invokeSsm(config, recoveryDeps, `set -eu\n/usr/bin/python3 - <<'PY'\n${check}\nPY`);
  return invokeSsm(config, recoveryDeps, `/usr/bin/python3 '${path}' '${action}'`, { expectResult: true });
}

async function recoverCanary(config, deps, lock, activePath) {
  if (lock.run_id !== lock.worker_run_id || !SAFE_WORKER_RUN_ID.test(lock.run_id))
    throw new ControllerError('canary run ownership is unavailable', 'WORKER_IDENTITY_INVALID', 5);
  const worker = validatedWorker(config, lock.worker_identity);
  if (worker.runId !== lock.run_id)
    throw new ControllerError('canary worker ownership differs from lock', 'WORKER_IDENTITY_INVALID', 5);
  if (lock.canary_phase) {
    const classified = await canaryReservationRecovery(config, deps, worker, 'classify');
    if (
      classified.schema_version !== 1 ||
      classified.externally_verified !== true ||
      JSON.stringify(validatedWorker(config, classified.worker_identity)) !== JSON.stringify(worker)
    )
      throw new ControllerError('worker phase authority unverified', 'RECOVERY_FAILED', 5);
    if (classified.prearm === true) {
      const evidence = await canaryReservationRecovery(config, deps, worker, 'prearm');
      if (
        evidence.schema_version !== 1 ||
        evidence.externally_verified !== true ||
        evidence.prearm !== true ||
        JSON.stringify(validatedWorker(config, evidence.worker_identity)) !== JSON.stringify(worker) ||
        evidence.restoration?.restored !== false ||
        evidence.restoration?.required !== false ||
        evidence.worker_artifacts_removed !== true ||
        evidence.reservation_artifacts_removed !== true
      )
        throw new ControllerError('prearm cleanup authority unverified', 'RECOVERY_FAILED', 5);
      await atomicReplace(activePath, {
        ...lock,
        recovery_kind: 'canary',
        recovery_evidence: evidence,
      });
      return {
        success: true,
        efficacy: 'NOT_TESTED',
        prearm: true,
        restoration: evidence.restoration,
        cleanup: { worker_artifacts_removed: true },
        reservation_cleanup: true,
      };
    }
  }
  const restoration = await canaryReservationRecovery(config, deps, worker, 'restore');
  if (
    restoration.schema_version !== 1 ||
    JSON.stringify(validatedWorker(config, restoration.worker_identity)) !== JSON.stringify(worker)
  )
    throw new ControllerError('restoration evidence ownership mismatch', 'WORKER_IDENTITY_INVALID', 5);
  if (
    restoration.externally_verified !== true ||
    restoration.restoration?.restored !== true ||
    restoration.restoration?.original_states_preserved !== true
  )
    throw new ControllerError('dispatcher restoration unverified', 'RECOVERY_FAILED', 5);
  const cleanup = await verifyCleanup(config, { ...deps, signal: undefined }, worker);
  if (!safetyPasses(cleanup)) throw new ControllerError('canary worker cleanup unverified', 'RECOVERY_FAILED', 5);
  await atomicReplace(activePath, {
    ...lock,
    recovery_kind: 'canary',
    recovery_evidence: restoration,
    worker_cleanup: cleanup,
  });
  const evidence = await canaryReservationRecovery(config, deps, worker, 'cleanup');
  if (
    evidence.schema_version !== 1 ||
    JSON.stringify(validatedWorker(config, evidence.worker_identity)) !== JSON.stringify(worker)
  )
    throw new ControllerError('cleanup evidence ownership mismatch', 'WORKER_IDENTITY_INVALID', 5);
  if (
    evidence.externally_verified !== true ||
    evidence.restoration?.restored !== true ||
    evidence.restoration?.original_states_preserved !== true ||
    evidence.worker_artifacts_removed !== true ||
    evidence.reservation_artifacts_removed !== true
  )
    throw new ControllerError('canary reservation cleanup unverified', 'RECOVERY_FAILED', 5);
  await atomicReplace(activePath, {
    ...lock,
    recovery_kind: 'canary',
    recovery_evidence: evidence,
    worker_cleanup: cleanup,
  });
  return {
    success: true,
    restoration: evidence.restoration,
    cleanup,
    reservation_cleanup: true,
  };
}

export async function recoverOnly(config, deps) {
  for (const key of [
    'awsProfile',
    'awsRegion',
    'awsAccount',
    'terraformDir',
    'trafficGeneratorTerraformDir',
    'f5ApiUrl',
    'f5ApiToken',
    'namespace',
    'lbName',
    'receiptDir',
  ])
    if (!config[key]) throw new ControllerError(`missing required configuration: ${key}`, 'CLI_ERROR', 2);
  if (
    config.header ||
    (config.browserMode && config.browserMode !== 'headless') ||
    (config.placement && config.placement !== 'mixed')
  )
    throw new ControllerError('recover-only rejects experiment and browser options', 'CLI_ERROR', 2);
  // A no-lock recovery must not contact deployment, browsers, traffic, or UUID sources.
  if (!(await status(config)).active)
    return {
      schema_version: 1,
      command: 'recover-only',
      success: true,
      no_op: true,
    };
  return recoverInterrupted(config, deps);
}

async function prepareRecoveryWorker(config, deps, original, activePath, originalCleanup) {
  const runId = randomUUID();
  const identity = workerIdentity(config, { runId, root: `/tmp/xcsh-csd-${runId}` });
  const lock = JSON.parse(await readFile(activePath, 'utf8'));
  await atomicReplace(activePath, {
    ...lock,
    recovery_worker_identity: identity,
    original_worker_cleanup: originalCleanup,
  });
  return validatedWorker(config, await prepareWorker(config, deps, runId, original));
}

async function recoverInterrupted(config, deps) {
  const state = await status(config);
  if (!state.active) return null;
  if (!state.interrupted && state.state !== 'recovery-required')
    throw new ControllerError('another Page Tamper experiment is active', 'OVERLAP', 5);
  const activePath = join(config.receiptDir, 'active.lock');
  const originalInode = await lstat(activePath);
  let lock = JSON.parse(await readFile(activePath, 'utf8'));
  if (
    !['canary', 'bootstrap', 'run', 'suite', 'suite-cleanup'].includes(lock.command) &&
    lock.recovery_kind !== 'canary'
  )
    throw new ControllerError('interrupted run kind cannot be proven', 'WORKER_IDENTITY_INVALID', 5);
  const workerRunId = lock.worker_run_id;
  if (
    (workerRunId === null && !deps.workerProbe) ||
    (workerRunId !== null && (typeof workerRunId !== 'string' || !SAFE_WORKER_RUN_ID.test(workerRunId)))
  )
    throw new ControllerError('original worker run reference is unavailable', 'WORKER_IDENTITY_INVALID', 5);
  const recoveryState = { ...state, worker_run_id: workerRunId };
  await bindLocalLock(activePath, lock, originalInode);
  let claim;
  try {
    claim = await claimRecovery(config, recoveryState, deps);
    lock = await ownedLocalLock(activePath, lock);
    let recovery;
    try {
      const outputs = await validateDeploymentIdentity(config, deps);
      if (lock.recovery_kind === 'canary' || lock.command === 'canary') {
        recovery = await recoverCanary(config, deps, lock, activePath);
      } else {
        const originalWorker =
          workerRunId === null
            ? null
            : workerIdentity(config, {
                runId: workerRunId,
                root: `/tmp/xcsh-csd-${workerRunId}`,
              });
        if (lock.recovery_worker_identity) {
          const pending = validatedWorker(config, lock.recovery_worker_identity);
          if (pending.runId === originalWorker?.runId)
            throw new ControllerError('recovery worker identity is not fresh', 'WORKER_IDENTITY_INVALID', 5);
          const pendingCleanup = await cleanupWorker(config, { ...deps, signal: undefined }, pending);
          if (!pendingCleanup.worker_artifacts_removed)
            throw new ControllerError('interrupted recovery worker cleanup unverified', 'RECOVERY_FAILED', 5);
        }
        const originalCleanup = originalWorker
          ? await cleanupWorker(config, { ...deps, signal: undefined }, originalWorker)
          : { worker_artifacts_removed: true };
        if (!originalCleanup.worker_artifacts_removed) {
          recovery = {
            success: false,
            cleanup: originalCleanup,
            error: {
              code: 'RECOVERY_FAILED',
              message: 'original worker remains active or unverified',
            },
          };
        } else {
          let recoveryWorker = null;
          if (originalWorker && !deps.workerProbe) {
            const runId = randomUUID();
            const identity = workerIdentity(config, { runId, root: `/tmp/xcsh-csd-${runId}` });
            lock = { ...lock, recovery_worker_identity: identity, original_worker_cleanup: originalCleanup };
            await atomicReplace(activePath, lock);
            recoveryWorker = validatedWorker(config, await prepareWorker(config, deps, runId, originalWorker));
          }
          recovery = await recover(config, deps, outputs, recoveryWorker);
          recovery.recovery_worker_identity = recoveryWorker;
        }
        recovery.original_worker_cleanup = originalCleanup;
      }
    } catch (error) {
      await preserveRecoveryLock(activePath, { ...recoveryState, recovery: { success: false } }, error, false);
      throw error;
    }
    const receipt = {
      schema_version: 1,
      run_id: state.run_id,
      worker_run_id: workerRunId,
      command: 'interruption-recovery',
      started_at: state.started_at,
      ended_at: deps.now(),
      recovery,
      success: recovery.success,
    };
    const path = join(config.receiptDir, `recovery-${state.run_id}-${Date.now()}.json`);
    try {
      await atomicReceipt(path, receipt);
    } catch (error) {
      await preserveRecoveryLock(activePath, receipt, error);
      throw new ControllerError('recovery completed but evidence persistence failed', 'EVIDENCE_PERSISTENCE_FAILED', 5);
    }
    if (!recovery.success) {
      await preserveRecoveryLock(
        activePath,
        receipt,
        new ControllerError('interrupted run recovery failed', 'RECOVERY_FAILED'),
        false,
      );
      throw new ControllerError('interrupted run recovery failed', 'RECOVERY_FAILED', 5);
    }
    try {
      await releaseRecoveryClaim(config, claim, deps);
      claim = null;
      await releaseOwnedLock(activePath);
    } catch (error) {
      await preserveRecoveryLock(activePath, receipt, error, false);
      throw error;
    }
    return receipt;
  } finally {
    if (claim) await releaseRecoveryClaim(config, claim, deps);
    await closeLocalLock(activePath);
  }
}

export async function runHeader(config, deps, headerId, options = {}) {
  if (!HEADER_IDS.includes(headerId)) throw new ControllerError(`unsupported header: ${headerId}`, 'INVALID_HEADER', 2);
  const outputs = await validateDeploymentIdentity(config, deps);
  if (!options.lockPath) await recoverInterrupted(config, deps);
  const runId = deps.randomUUID();
  const startedAt = deps.now();
  const worker = options.worker
    ? validatedWorker(config, options.worker)
    : deps.workerProbe
      ? null
      : workerIdentity(config, { runId, root: `/tmp/xcsh-csd-${runId}` });
  const lockPath = options.lockPath || (await acquireLock(config, runId, deps.now, 'run', worker));
  const finalizeWorker = options.finalizeWorker !== false;
  const receipt = {
    schema_version: 1,
    run_id: runId,
    worker_run_id: worker?.runId || null,
    command: 'run',
    header_id: headerId,
    started_at: startedAt,
    ended_at: null,
    phases: {},
    alerts: [],
    outcome: 'INVALID_TEST',
    recovery: null,
  };
  let finalizationError;
  let workerPrepared = Boolean(options.worker);
  const payloads = [];
  try {
    if (worker && !options.worker) {
      await prepareWorker(config, deps, runId);
      workerPrepared = true;
    }
    receipt.phases.control_reinforcement = {
      required: config.timings.reinforcementProfiles,
      completed: 0,
      valid: true,
    };
    const reinforcementDeadline = deps.nowMs() + config.timings.reinforcementMs;
    for (let index = 0; index < config.timings.reinforcementProfiles; index++) {
      if (!validProbe(await browserProbe(config, deps, null, 'workstation', worker)))
        throw new ControllerError('control reinforcement probe failed', 'INVALID_TEST');
      receipt.phases.control_reinforcement.completed++;
    }
    await sleep(deps, Math.max(0, reinforcementDeadline - deps.nowMs()));
    const windowStart = deps.now();
    const deadline = Math.min(
      Date.parse(startedAt) + config.timings.maximumCaseMs,
      Date.parse(windowStart) + config.timings.mixedMs,
    );
    const expected = {
      namespace: config.namespace,
      origin: new URL(config.target).origin,
      path: PAYMENT_PATH,
      headerId,
      windowStart,
      windowEnd: new Date(deadline).toISOString(),
    };
    receipt.phases.mixed = {
      required_pairs: config.timings.minimumPairs,
      completed_pairs: 0,
      telemetry_valid: true,
    };
    let compromised = false;
    let finalPolled = false;
    while (deps.nowMs() < deadline && !compromised) {
      if (receipt.phases.mixed.completed_pairs < config.timings.minimumPairs) {
        const control = await browserProbe(config, deps, null, 'workstation', worker);
        const tampered = await browserProbe(config, deps, headerId, 'workstation', worker);
        if (!validProbe(control) || !validProbe(tampered, headerId))
          throw new ControllerError('mixed cohort evidence failed', 'INVALID_TEST');
        receipt.phases.mixed.completed_pairs++;
      }
      payloads.push(await pollAlerts(config, deps, expected));
      receipt.alerts = correlateBoundedPayloads(payloads, expected);
      compromised = receipt.alerts.some(({ alert_name }) => alert_name === 'ClientSideDefenseHttpHeaderCompromised');
      if (!compromised)
        await sleep(deps, Math.min(Math.max(1, config.timings.pollMs), Math.max(1, deadline - deps.nowMs())));
    }
    if (!compromised) {
      payloads.push(await pollAlerts(config, deps, expected));
      finalPolled = true;
      receipt.alerts = correlateBoundedPayloads(payloads, expected);
    }
    receipt.phases.mixed.final_poll = finalPolled;
    receipt.outcome = classifyAlerts(
      receipt.alerts,
      compromised || receipt.phases.mixed.completed_pairs >= config.timings.minimumPairs,
    );
  } catch (error) {
    receipt.error = {
      code: error.code || 'INVALID_TEST',
      message: String(error.message).slice(0, 240),
    };
    receipt.outcome = 'INVALID_TEST';
  } finally {
    try {
      if (worker && !workerPrepared) {
        const originalCleanup = await cleanupWorker(config, { ...deps, signal: undefined }, worker);
        receipt.recovery = originalCleanup.worker_artifacts_removed
          ? {
              ...(await recover(
                config,
                deps,
                outputs,
                await prepareRecoveryWorker(config, deps, worker, lockPath, originalCleanup),
                finalizeWorker,
              )),
              original_worker_cleanup: originalCleanup,
            }
          : { success: false, original_worker_cleanup: originalCleanup };
      } else receipt.recovery = await recover(config, deps, outputs, worker, finalizeWorker);
      if (!receipt.recovery.success) receipt.outcome = 'INVALID_TEST';
    } catch (error) {
      receipt.recovery = {
        success: false,
        error: {
          code: error.code || 'RECOVERY_FAILED',
          message: String(error.message).slice(0, 240),
        },
      };
      receipt.outcome = 'INVALID_TEST';
    }
    receipt.ended_at = deps.now();
    const path = join(config.receiptDir, `${receipt.started_at.replace(/[:.]/g, '-')}-${headerId}-${runId}.json`);
    try {
      await atomicReceipt(path, receipt);
      if (!options.lockPath) {
        if (receipt.recovery?.success) await releaseOwnedLock(lockPath);
        else await preserveRecoveryLock(lockPath, receipt, new ControllerError('recovery failed', 'RECOVERY_FAILED'));
      }
    } catch (error) {
      if (!options.lockPath) await preserveRecoveryLock(lockPath, receipt, error);
      finalizationError = new ControllerError(
        'recovery result could not be persisted; lock retained',
        'EVIDENCE_PERSISTENCE_FAILED',
        5,
      );
    }
  }
  if (finalizationError) throw finalizationError;
  return receipt;
}

export async function bootstrap(config, deps, options = {}) {
  const outputs = await validateDeploymentIdentity(config, deps);
  if (!options.lockPath) await recoverInterrupted(config, deps);
  const finder = deps.randomUUID();
  const worker =
    options.worker ||
    (deps.workerProbe
      ? null
      : workerIdentity(config, {
          runId: finder,
          root: `/tmp/xcsh-csd-${finder}`,
        }));
  const lockPath = options.lockPath || (await acquireLock(config, finder, deps.now, 'bootstrap', worker));
  const startedAt = deps.now();
  const receipt = {
    schema_version: 1,
    run_id: finder,
    worker_run_id: worker?.runId || null,
    command: 'bootstrap',
    started_at: startedAt,
    ended_at: null,
    success: false,
    recovery: null,
  };
  let primaryError;
  let finalizationError;
  let workerCleanupFailed = false;
  let workerPrepared = Boolean(options.worker);
  try {
    if (worker && !options.worker) {
      await prepareWorker(config, deps, finder);
      workerPrepared = true;
    }
    const drift = await noDrift(config, deps);
    if (!drift.no_drift) throw new ControllerError('Terraform plan is not clean', 'DRIFT');
    const ready = await readiness(config, deps, outputs);
    if (!safetyPasses(ready)) throw new ControllerError('deployment readiness failed', 'READINESS_FAILED');
    await controlPair(config, deps, worker);
    const controlDeadline = deps.nowMs() + config.timings.bootstrapControlMs;
    const payloads = [];
    while (deps.nowMs() < controlDeadline) {
      await controlPair(config, deps, worker);
      payloads.push(...(await pollCandidateAlerts(config, deps, startedAt, new Date(controlDeadline).toISOString())));
      await sleep(deps, Math.min(Math.max(1, config.timings.pollMs), Math.max(1, controlDeadline - deps.nowMs())));
    }
    const knownFiring = new Set();
    const seenFiring = new Set();
    const initialAlerts = correlateCandidateAlerts(payloads, config, startedAt, deps.now());
    initialAlerts
      .filter(({ state }) => state === 'firing')
      .forEach((alert) => {
        seenFiring.add(alertIdentity(alert));
      });
    observeAlertLifecycle(knownFiring, initialAlerts);
    let quietStart = knownFiring.size === 0 ? deps.nowMs() : null;
    const quietOuterDeadline = deps.nowMs() + config.timings.quietMs * 2 + Math.max(1, config.timings.pollMs);
    while (config.timings.quietMs > 0 && (quietStart === null || deps.nowMs() - quietStart < config.timings.quietMs)) {
      if (deps.nowMs() >= quietOuterDeadline)
        throw new ControllerError('full quiet window was not observed before outer deadline', 'QUIET_WINDOW_FAILED');
      const polled = await pollCandidateAlerts(config, deps, startedAt, deps.now());
      payloads.push(...polled);
      const correlated = correlateCandidateAlerts(polled, config, startedAt, deps.now(), knownFiring);
      correlated
        .filter(({ state }) => state === 'firing')
        .forEach((alert) => {
          seenFiring.add(alertIdentity(alert));
        });
      const observedFiring = observeAlertLifecycle(knownFiring, correlated);
      if (knownFiring.size > 0 || observedFiring) quietStart = null;
      else if (quietStart === null) quietStart = deps.nowMs();
      await sleep(deps, Math.min(Math.max(1, config.timings.pollMs), Math.max(1, quietOuterDeadline - deps.nowMs())));
    }
    receipt.readiness = ready;
    receipt.no_drift = drift;
    receipt.alerts = correlateCandidateAlerts(payloads, config, startedAt, deps.now(), seenFiring);
    receipt.success = true;
  } catch (error) {
    primaryError = error;
    receipt.error = {
      code: error.code || 'BOOTSTRAP_FAILED',
      message: String(error.message).slice(0, 240),
    };
    if (worker && !workerPrepared) {
      receipt.recovery = {
        success: false,
        error: {
          code: 'RECOVERY_FAILED',
          message: 'worker preparation incomplete; original root requires cleanup',
        },
      };
    } else {
      try {
        receipt.recovery = await recover(config, deps, outputs, worker);
      } catch (recoveryError) {
        receipt.recovery = {
          success: false,
          error: {
            code: recoveryError.code || 'RECOVERY_FAILED',
            message: String(recoveryError.message).slice(0, 240),
          },
        };
      }
    }
  } finally {
    if (worker && options.finalizeWorker !== false) {
      const cleanup = await cleanupWorker(config, { ...deps, signal: undefined }, worker);
      if (!cleanup.worker_artifacts_removed) {
        workerCleanupFailed = true;
        const cleanupError = new ControllerError('worker cleanup failed', 'RECOVERY_FAILED');
        primaryError ||= cleanupError;
        receipt.error ||= {
          code: cleanupError.code,
          message: cleanupError.message,
        };
        receipt.success = false;
        receipt.recovery = { ...receipt.recovery, success: false, cleanup };
      }
    }
    receipt.ended_at = deps.now();
    const path = join(config.receiptDir, `bootstrap-${finder}${receipt.success ? '' : '-failed'}.json`);
    try {
      await atomicReceipt(path, receipt);
      if (!options.lockPath) {
        if (!workerCleanupFailed && (receipt.success || receipt.recovery?.success)) await releaseOwnedLock(lockPath);
        else
          await preserveRecoveryLock(
            lockPath,
            receipt,
            workerCleanupFailed
              ? new ControllerError('worker cleanup failed', 'RECOVERY_FAILED')
              : primaryError || new Error('bootstrap recovery failed'),
            !workerCleanupFailed,
          );
      }
    } catch (error) {
      if (!options.lockPath) await preserveRecoveryLock(lockPath, receipt, error);
      finalizationError = new ControllerError(
        'bootstrap evidence could not be persisted; lock retained',
        'EVIDENCE_PERSISTENCE_FAILED',
        5,
      );
    }
  }
  if (finalizationError) throw finalizationError;
  if (primaryError) throw primaryError;
  return receipt;
}

export async function runCanary(config, deps) {
  if (config.browserMode !== 'headed-xvfb' || config.placement !== 'worker')
    throw new ControllerError('single canary requires headed-xvfb and worker placement', 'CLI_ERROR', 2);
  await validateDeploymentIdentity(config, deps);
  await recoverInterrupted(config, deps);
  const runId = deps.randomUUID();
  const identity = workerIdentity(config, {
    runId,
    root: `/tmp/xcsh-csd-${runId}`,
  });
  const lockPath = await acquireLock(config, runId, deps.now, 'canary', identity);
  let worker = identity;
  const guarded = { ...config, reservationWorker: identity };
  let armed = false;
  let result;
  let error;
  try {
    const phase = async (canary_phase) => {
      const lock = await ownedLocalLock(lockPath);
      await atomicReplace(lockPath, { ...lock, canary_phase });
    };
    const initialized = await canaryReservationRecovery(guarded, deps, identity, 'initialize');
    if (
      initialized?.schema_version !== 1 ||
      initialized.externally_verified !== true ||
      JSON.stringify(validatedWorker(guarded, initialized.worker_identity)) !== JSON.stringify(identity)
    )
      throw new ControllerError('worker initialization authority unverified', 'RECOVERY_FAILED', 5);
    await phase('prepare_intent');
    if (!deps.workerProbe) worker = await prepareWorker(guarded, deps, runId);
    await phase('arm_intent');
    const guard = await reservationAction(guarded, deps, worker, 'arm');
    if (!guard.armed || !guard.dispatch_drained) throw new ControllerError('reservation not verified', 'INVALID_TEST');
    armed = true;
    await phase('armed');
    await bootstrap(guarded, deps, { worker, finalizeWorker: false, lockPath });
    result = await runHeader(guarded, deps, 'x-content-type-options', {
      worker,
      finalizeWorker: false,
      lockPath,
    });
  } catch (failure) {
    error = failure;
  }
  // Worker authority decides prearm rollback versus original dispatch restoration.
  try {
    const lock = await ownedLocalLock(lockPath);
    const recovery = await recoverCanary(guarded, deps, lock, lockPath);
    if (!result)
      await atomicReceipt(join(config.receiptDir, `canary-${runId}-failed.json`), {
        schema_version: 1,
        run_id: runId,
        command: 'canary',
        outcome: 'INVALID_TEST',
        efficacy: 'NOT_TESTED',
        success: false,
        recovery,
        error: {
          code: error?.code || 'CANARY_FAILED',
          message: 'canary did not complete',
        },
      });
    if (result)
      result.reservation = {
        armed,
        restored: true,
        original_states_preserved: true,
      };
    if (result) result.browser_provenance = guarded.browserProvenance;
    if (result) await atomicReceipt(join(config.receiptDir, `canary-${runId}.json`), result);
    if (!result || result.recovery?.success) await releaseOwnedLock(lockPath);
    else throw new ControllerError('canary recovery failed', 'RECOVERY_FAILED');
  } catch (failure) {
    await mkdir(config.receiptDir, { recursive: true, mode: 0o700 });
    await preserveRecoveryLock(
      join(config.receiptDir, 'active.lock'),
      {
        run_id: runId,
        worker_run_id: worker?.runId,
        command: 'canary',
        started_at: deps.now(),
        recovery: { success: false },
      },
      failure,
      false,
    );
    error = new ControllerError('canary restoration or cleanup unverified; lock retained', 'RECOVERY_FAILED', 5);
  }
  if (error) throw error;
  return result;
}

export async function runSuite(config, deps) {
  await validateDeploymentIdentity(config, deps);
  await recoverInterrupted(config, deps);
  const results = [];
  const suiteId = deps.randomUUID();
  const startedAt = deps.now();
  const worker = deps.workerProbe ? null : await prepareWorker(config, deps, suiteId);
  let cleanup = { worker_artifacts_removed: true };
  let cleanupError = null;
  try {
    for (const headerId of [
      'x-content-type-options',
      ...HEADER_IDS.filter((item) => item !== 'x-content-type-options'),
    ]) {
      const result = await runHeader(config, deps, headerId, {
        worker,
        finalizeWorker: false,
      });
      results.push({
        header_id: headerId,
        outcome: result.outcome,
        recovery_success: result.recovery?.success === true,
      });
      if (headerId === 'x-content-type-options' && result.outcome !== 'COMPROMISED') break;
    }
  } finally {
    try {
      cleanup = await verifyCleanup(config, { ...deps, signal: undefined }, worker, true);
    } catch {
      cleanupError = new ControllerError('suite cleanup failed', 'CLEANUP_FAILED', 5);
      cleanup = {
        worker_artifacts_removed: false,
        browser_artifacts_removed: false,
        error: { code: cleanupError.code, message: cleanupError.message },
      };
    }
  }
  const receipt = {
    schema_version: 1,
    run_id: suiteId,
    worker_run_id: worker?.runId || null,
    command: 'suite',
    started_at: startedAt,
    ended_at: deps.now(),
    results,
    cleanup,
    ...(cleanupError ? { error: { code: cleanupError.code, message: cleanupError.message } } : {}),
    success:
      results.length === HEADER_IDS.length &&
      results.every(({ outcome, recovery_success }) => outcome === 'COMPROMISED' && recovery_success) &&
      safetyPasses(cleanup),
  };
  await mkdir(config.receiptDir, { recursive: true, mode: 0o700 });
  await atomicReceipt(join(config.receiptDir, `suite-${suiteId}.json`), receipt);
  if (!safetyPasses(cleanup)) {
    const lockPath = join(config.receiptDir, 'active.lock');
    await acquireLock(config, suiteId, deps.now, 'suite-cleanup', worker);
    await preserveRecoveryLock(
      lockPath,
      { ...receipt, recovery: { success: false } },
      cleanupError || new ControllerError('suite worker cleanup failed', 'RECOVERY_FAILED'),
    );
  }
  return receipt;
}

export async function status(config) {
  const path = join(config.receiptDir, 'active.lock');
  try {
    const lock = JSON.parse(await readFile(path, 'utf8'));
    const details = await stat(path);
    const persistenceFailure = lock.evidence_persistence_failure === true;
    const ageExpired = Date.now() - details.mtimeMs > config.timings.maximumCaseMs;
    return {
      schema_version: 2,
      active: true,
      state: lock.state || 'active',
      interrupted: persistenceFailure || ageExpired || lock.state === 'recovery-required',
      run_id: lock.run_id,
      command: lock.command,
      started_at: lock.started_at,
      cleanup_required: true,
      evidence_persistence_failure: persistenceFailure,
    };
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
    return {
      schema_version: 2,
      active: false,
      interrupted: false,
      cleanup_required: false,
      evidence_persistence_failure: false,
    };
  }
}

export function createDependencies(overrides = {}) {
  return {
    executor: overrides.executor || defaultExecutor,
    fetch: overrides.fetch || globalThis.fetch,
    WebSocket: overrides.WebSocket || globalThis.WebSocket,
    sleep:
      overrides.sleep ||
      ((ms, signal) =>
        new Promise((resolve, reject) => {
          const timer = setTimeout(resolve, ms);
          signal?.addEventListener(
            'abort',
            () => {
              clearTimeout(timer);
              reject(new ControllerError('interrupted', 'INTERRUPTED'));
            },
            { once: true },
          );
        })),
    now: overrides.now || (() => new Date().toISOString()),
    nowMs: overrides.nowMs || Date.now,
    randomUUID: overrides.randomUUID || randomUUID,
    env: overrides.env || process.env,
    signal: overrides.signal,
    cdp: overrides.cdp,
    probe: overrides.probe,
    workerProbe: overrides.workerProbe,
    alertSource: overrides.alertSource,
    readiness: overrides.readiness,
    cleanup: overrides.cleanup,
    reservation: overrides.reservation,
    reservationRecovery: overrides.reservationRecovery,
    readFile: overrides.readFile || readFile,
    remove: overrides.remove || rm,
    commandTimeoutMs: overrides.commandTimeoutMs || DEFAULT_TIMINGS.commandTimeoutMs,
  };
}
