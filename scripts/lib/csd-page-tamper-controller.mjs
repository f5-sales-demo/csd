import { spawn } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { link, mkdir, open, readFile, rename, rm, stat, writeFile } from 'node:fs/promises';
import { hostname } from 'node:os';
import { basename, dirname, join } from 'node:path';
import { Readable, Writable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { fileURLToPath } from 'node:url';
import { createGzip } from 'node:zlib';
import { DOCUMENT_PROBE_HEADERS, DOCUMENT_PROBE_PATH, DOCUMENT_PROBE_SELECTOR_IDS } from './csd-config.mjs';
import { classifyAlerts, correlateAlerts, correlateAlertViews } from './csd-page-tamper-alerts.mjs';
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
  awsProfile: 'Users-280469140135',
  awsRegion: 'us-east-1',
  namespace: 'client-side-defense',
  lbName: 'client-side-defense',
  backendBucket: 'terraform-tfstate-xc',
  backendKey: 'f5-sales-demo/client-side-defense.tfstate',
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
    const child = spawn(argv[0], argv.slice(1), { cwd, env, signal, shell: false, stdio: ['ignore', 'pipe', 'pipe'] });
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
      resolve({ code, stdout: Buffer.concat(stdout).toString(), stderr: Buffer.concat(stderr).toString() });
    });
  });
}

const command = async (deps, argv, options = {}) => {
  const result = await deps.executor(argv, { ...options, timeoutMs: options.timeoutMs ?? deps.commandTimeoutMs });
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
  if (
    !versions.includes(`bucket       = "${REVIEWED.backendBucket}"`) ||
    !versions.includes(`key          = "${REVIEWED.backendKey}"`)
  )
    throw new ControllerError('Terraform backend does not match the reviewed deployment', 'IDENTITY_MISMATCH', 3);
  const caller = parseJson(
    await command(deps, ['aws', 'sts', 'get-caller-identity', '--profile', config.awsProfile, '--output', 'json']),
    'AWS_INVALID_JSON',
  );
  assertValue(String(caller.Account), REVIEWED.awsAccount, 'active AWS account');
  const worker = parseJson(
    await command(deps, [
      'aws',
      'ec2',
      'describe-instances',
      '--instance-ids',
      config.workerInstance,
      ...awsBase(config),
    ]),
    'AWS_INVALID_JSON',
  );
  const instances = worker.Reservations?.flatMap(({ Instances = [] }) => Instances) || [];
  if (instances.length !== 1 || instances[0].State?.Name !== 'running')
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

async function acquireLock(config, runId, now, commandName) {
  await mkdir(config.receiptDir, { recursive: true, mode: 0o700 });
  const path = join(config.receiptDir, 'active.lock');
  let handle;
  try {
    handle = await open(path, 'wx', 0o600);
    await handle.writeFile(
      `${JSON.stringify({
        schema_version: 1,
        run_id: runId,
        command: commandName,
        started_at: now(),
        state: 'active',
        hostname: hostname(),
        pid: process.pid,
      })}\n`,
    );
    await handle.sync();
    return path;
  } catch (error) {
    if (error.code === 'EEXIST') throw new ControllerError('another Page Tamper experiment is active', 'OVERLAP', 5);
    throw error;
  } finally {
    await handle?.close();
  }
}

async function atomicReplace(path, value) {
  const temp = join(dirname(path), `.${basename(path)}.${process.pid}.${randomUUID()}.tmp`);
  await writeFile(temp, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600, flag: 'wx' });
  await rename(temp, path);
}
async function atomicReceipt(path, value) {
  const temp = join(dirname(path), `.${basename(path)}.${process.pid}.${randomUUID()}.tmp`);
  try {
    await writeFile(temp, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600, flag: 'wx' });
    await link(temp, path);
  } finally {
    await rm(temp, { force: true });
  }
}
async function preserveRecoveryLock(lockPath, receipt, error) {
  await atomicReplace(lockPath, {
    schema_version: 1,
    run_id: receipt.run_id,
    command: receipt.command,
    started_at: receipt.started_at,
    state: 'recovery-required',
    recovery_completed: receipt.recovery?.success === true,
    evidence_persistence_failure: true,
    error: { code: error.code || 'RECEIPT_WRITE_FAILED', message: String(error.message).slice(0, 160) },
  });
}

async function withRecoveryClaimGate(config, callback) {
  const gatePath = join(config.receiptDir, 'recovery.claim.guard');
  try {
    await mkdir(gatePath, { mode: 0o700 });
  } catch (error) {
    if (error.code === 'EEXIST') throw new ControllerError('interrupted recovery claim is changing', 'OVERLAP', 5);
    throw error;
  }
  try {
    return await callback();
  } finally {
    await rm(gatePath, { recursive: true, force: true });
  }
}

async function claimRecovery(config, state, deps) {
  const path = join(config.receiptDir, 'recovery.claim');
  const ownerPath = join(path, 'owner.json');
  const claimId = deps.randomUUID();
  const value = {
    schema_version: 1,
    claim_id: claimId,
    run_id: state.run_id,
    original_command: state.command || null,
    original_started_at: state.started_at,
    claimed_at: deps.now(),
    hostname: deps.hostname(),
    pid: deps.pid(),
  };
  return withRecoveryClaimGate(config, async () => {
    try {
      await mkdir(path, { mode: 0o700 });
    } catch (error) {
      if (error.code !== 'EEXIST') throw error;
      const before = await stat(path).catch(() => null);
      const current = before ? JSON.parse(await readFile(ownerPath, 'utf8')) : null;
      const sameHostDead =
        current?.hostname === deps.hostname() && Number.isInteger(current?.pid) && !deps.isProcessAlive(current.pid);
      if (!sameHostDead && (!before || deps.nowMs() - before.mtimeMs <= config.timings.maximumCaseMs))
        throw new ControllerError('interrupted recovery is already claimed', 'OVERLAP', 5);
      const after = await stat(path).catch(() => null);
      if (!after || before.dev !== after.dev || before.ino !== after.ino || before.mtimeMs !== after.mtimeMs)
        throw new ControllerError('interrupted recovery claim changed during takeover', 'OVERLAP', 5);
      const preserved = join(
        config.receiptDir,
        `recovery-claim-stale-${state.run_id}-${deps.nowMs()}-${current.claim_id}.json`,
      );
      await writeFile(preserved, `${JSON.stringify(current, null, 2)}\n`, { mode: 0o600, flag: 'wx' });
      await rm(path, { recursive: true });
      await mkdir(path, { mode: 0o700 });
    }
    await writeFile(ownerPath, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600, flag: 'wx' });
    return { path, ownerPath, claimId };
  });
}

async function releaseRecoveryClaim(config, claim, deps) {
  return withRecoveryClaimGate(config, async () => {
    const current = JSON.parse(await deps.readFile(claim.ownerPath, 'utf8'));
    if (current.claim_id !== claim.claimId) throw new ControllerError('recovery claim ownership changed', 'OVERLAP', 5);
    await deps.remove(claim.path, { recursive: true });
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
  const response = await deps.fetch(new URL('/json/version', endpoint), { signal: deps.signal });
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
const SSM_CHUNK_SIZE = 3000;

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
    throw new ControllerError('worker SSM command did not complete successfully inline', 'SSM_FAILED');
  if (!expectResult) return invocation;
  const output = String(invocation.StandardOutputContent || '');
  const lines = output.split('\n').filter((line) => line.startsWith('XCSH_RESULT '));
  if (lines.length !== 1 || output.length >= 24_000)
    throw new ControllerError('worker SSM output was missing, ambiguous, or truncated', 'SSM_OUTPUT_INVALID');
  return parseJson(lines[0].slice('XCSH_RESULT '.length), 'SSM_OUTPUT_INVALID');
}

export async function prepareWorker(config, deps, runId = deps.randomUUID()) {
  const root = `/tmp/xcsh-csd-${runId}`;
  const archive = await gzipBuffer(workerArchiveEntries(await workerSources(deps)));
  const encoded = archive.toString('base64');
  const sha256 = createHash('sha256').update(archive).digest('hex');
  const archivePath = `${root}/sources.gz`;
  try {
    await invokeSsm(
      config,
      deps,
      `set -eu;umask 077;run='${root}';rm -rf "$run";mkdir -p "$run";: >'${archivePath}.b64'`,
    );
    for (let offset = 0; offset < encoded.length; offset += SSM_CHUNK_SIZE) {
      const chunk = encoded.slice(offset, offset + SSM_CHUNK_SIZE);
      await invokeSsm(config, deps, `set -eu;printf %s '${chunk}' >>'${archivePath}.b64'`);
    }
    const extraction = `set -eu;run='${root}';base64 -d '${archivePath}.b64' >'${archivePath}';actual=$(sha256sum '${archivePath}'|cut -d' ' -f1);[ "$actual" = '${sha256}' ]||exit 41;rm -f '${archivePath}.b64';python3 - "$run" '${archivePath}' <<'PY'\nimport gzip,pathlib,sys\nout=pathlib.Path(sys.argv[1]);data=gzip.open(sys.argv[2],'rt').read();i=0\nwhile i<len(data):\n c=data.find(':',i);n=int(data[i:c]);name=data[c+1:c+1+n];i=c+1+n;c=data.find(':',i);size=int(data[i:c]);body=data[c+1:c+1+size];i=c+1+size;(out/name).write_text(body)\nPY\nchown -R ubuntu:ubuntu "$run";chmod -R go-rwx "$run"`;
    await invokeSsm(config, deps, extraction);
    return { runId, root, sha256 };
  } catch (error) {
    try {
      await invokeSsm(config, deps, `rm -rf '${root}';[ ! -e '${root}' ]`);
    } catch {}
    throw error;
  }
}

export async function cleanupWorker(config, deps, worker) {
  if (!worker) return { worker_artifacts_removed: true };
  try {
    await invokeSsm(config, deps, `set -eu;rm -rf '${worker.root}';[ ! -e '${worker.root}' ]`);
    return { worker_artifacts_removed: true };
  } catch {
    return { worker_artifacts_removed: false };
  }
}

export async function runWorkerProbe(config, deps, headerId = null, worker = null) {
  const owned = worker || (await prepareWorker(config, deps));
  const probeId = deps.randomUUID();
  const probeRoot = `${owned.root}/probe-${probeId}`;
  const entry = Buffer.from(
    `import { CdpClient, runDocumentProbe } from '${owned.root}/csd-runner.mjs';\nconst version=await fetch('http://127.0.0.1:9222/json/version');const body=await version.json();const cdp=await CdpClient.connect(body.webSocketDebuggerUrl,${Number(config.probeTimeoutMs)},WebSocket);try{const result=await runDocumentProbe(${JSON.stringify(probeOptions(config, headerId))},{cdp});console.log('XCSH_RESULT '+JSON.stringify(result));}finally{cdp.close();}`,
  ).toString('base64');
  const userScript = `#!/bin/sh
set -eu;probe='${probeRoot}';profile="$probe/profile";pidfile="$probe/chrome.pid";spawn="$probe/chrome-launch";pid='';pgid='';launcher_pid=$$;launcher_pgid=$(ps -o pgid= -p $$|tr -d ' ');alive(){ kill -0 "$pid" 2>/dev/null||kill -0 -- "-$pgid" 2>/dev/null;};cleanup(){ rc=0;if [ -s "$pidfile" ];then read pid pgid <"$pidfile"||rc=1;fi;case "$pid:$pgid" in :*|*:|*[!0-9:]*|0:*|*:0) rc=1;;esac;if [ "$rc" -eq 0 ]&&{ [ "$pid" = "$launcher_pid" ]||[ "$pgid" = "$launcher_pgid" ];};then rc=1;fi;if [ "$rc" -eq 0 ];then kill -TERM -- "-$pgid" 2>/dev/null||kill -TERM "$pid" 2>/dev/null||true;i=0;while alive&&[ "$i" -lt 5 ];do i=$((i+1));sleep 1;done;if alive;then kill -KILL -- "-$pgid" 2>/dev/null||kill -KILL "$pid" 2>/dev/null||true;i=0;while alive&&[ "$i" -lt 5 ];do i=$((i+1));sleep 1;done;fi;if alive;then echo "chrome cleanup timeout pid=$pid pgid=$pgid" >&2;rc=1;fi;else echo "unsafe chrome identity pid=$pid pgid=$pgid launcher=$launcher_pid/$launcher_pgid" >&2;fi;i=0;while [ "$i" -lt 5 ]&&[ -e "$probe" ];do rm -rf "$probe";[ ! -e "$probe" ]||sleep 1;i=$((i+1));done;if [ -e "$probe" ];then echo "probe cleanup timeout path=$probe" >&2;rc=1;fi;return "$rc";};trap 'cleanup||true' EXIT INT TERM;umask 077;mkdir -p "$profile";printf %s '${entry}'|base64 -d >"$probe/entry.mjs";node_bin='';for c in /opt/node/bin/node node;do if [ -x "$c" ];then node_bin="$c";break;fi;if command -v "$c" >/dev/null 2>&1;then node_bin=$(command -v "$c");break;fi;done;[ -n "$node_bin" ]||exit 36;chrome='';for c in /opt/chrome/chrome google-chrome-stable google-chrome chromium chromium-browser;do if command -v "$c" >/dev/null 2>&1;then chrome=$(command -v "$c");break;fi;done;[ -n "$chrome" ]||exit 31;[ -x /usr/bin/setsid ]||exit 37;cat >"$spawn" <<'SH'
#!/bin/sh
set -eu;pidfile=$1;shift;pid=$$;pgid=$(ps -o pgid= -p $$|tr -d ' ');printf '%s %s\\n' "$pid" "$pgid" >"$pidfile";exec "$@"
SH
chmod 700 "$spawn";/usr/bin/setsid --fork "$spawn" "$pidfile" "$chrome" --headless=new --no-first-run --no-default-browser-check --remote-debugging-address=127.0.0.1 --remote-debugging-port=9222 --user-data-dir="$profile" about:blank >/dev/null 2>&1;i=0;while [ ! -s "$pidfile" ];do i=$((i+1));[ "$i" -lt 10 ]||exit 38;sleep 1;done;read pid pgid <"$pidfile";case "$pid:$pgid" in :*|*:|*[!0-9:]*|0:*|*:0) exit 39;;esac;if [ "$pid" = "$launcher_pid" ]||[ "$pid" = "$launcher_pgid" ]||[ "$pgid" = "$launcher_pid" ]||[ "$pgid" = "$launcher_pgid" ];then exit 39;fi;i=0;until "$node_bin" -e "fetch('http://127.0.0.1:9222/json/version').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))";do i=$((i+1));[ "$i" -lt 60 ]||exit 32;sleep 1;done;"$node_bin" "$probe/entry.mjs";cleanup||exit 34;trap - EXIT INT TERM`;
  const encodedScript = Buffer.from(userScript).toString('base64');
  const launcher = `${owned.root}/.launch-${probeId}`;
  const encodedLauncher = `${launcher}.b64`;
  try {
    await invokeSsm(config, deps, `set -eu;umask 077;: >'${encodedLauncher}'`);
    for (let offset = 0; offset < encodedScript.length; offset += SSM_CHUNK_SIZE)
      await invokeSsm(
        config,
        deps,
        `set -eu;printf %s '${encodedScript.slice(offset, offset + SSM_CHUNK_SIZE)}' >>'${encodedLauncher}'`,
      );
    const script = `set -eu;launcher='${launcher}';encoded='${encodedLauncher}';cleanup(){ rm -f "$launcher" "$encoded"; };trap cleanup EXIT INT TERM;umask 077;base64 -d "$encoded" >"$launcher";chown ubuntu:ubuntu "$launcher";chmod 700 "$launcher";sudo -u ubuntu -H "$launcher";cleanup;[ ! -e '${probeRoot}' ]||exit 35;trap - EXIT INT TERM`;
    return await invokeSsm(config, deps, script, { expectResult: true });
  } finally {
    if (!worker) await cleanupWorker(config, deps, owned);
  }
}

async function browserProbe(config, deps, headerId = null, location = 'workstation', worker = null) {
  if (deps.probe) return deps.probe({ config, headerId, location, worker });
  if (location === 'worker')
    return deps.workerProbe
      ? deps.workerProbe({ config, headerId, options: probeOptions(config, headerId), worker })
      : runWorkerProbe(config, deps, headerId, worker);
  const cdp = deps.cdp || (await connectCdp(config, deps));
  try {
    return await runDocumentProbe(probeOptions(config, headerId), { cdp, signal: deps.signal });
  } finally {
    if (!deps.cdp) cdp.close();
  }
}

async function pollAlerts(config, deps, expected) {
  if (deps.alertSource) return deps.alertSource(expected);
  const headers = { Authorization: `APIToken ${config.f5ApiToken}` };
  const base = REVIEWED.f5ApiOrigin;
  const [current, history] = await Promise.all(
    [
      `${base}/api/data/namespaces/${encodeURIComponent(config.namespace)}/alerts`,
      `${base}/api/data/namespaces/${encodeURIComponent(config.namespace)}/alerts/history`,
    ].map(async (url) => {
      const response = await deps.fetch(url, { headers, signal: deps.signal });
      if (!response.ok) throw new ControllerError('alert telemetry request failed', 'TELEMETRY_GAP');
      return response.json();
    }),
  );
  return { current, history };
}

function alertViews(payload) {
  if (payload && !Array.isArray(payload) && ('current' in payload || 'history' in payload))
    return { current: payload.current || [], history: payload.history || [] };
  if (!Array.isArray(payload)) return { current: payload ? [payload] : [], history: [] };
  return { current: payload[0] || [], history: payload.slice(1) };
}

function alertExpected(config, headerId, windowStart, windowEnd) {
  return { namespace: config.namespace, path: PAYMENT_PATH, headerId, windowStart, windowEnd };
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
    if (payload && !Array.isArray(payload) && ('current' in payload || 'history' in payload))
      return correlateAlerts([payload.current || [], payload.history || []], expected);
    return correlateAlerts([payload], expected);
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
    await invokeSsm(
      config,
      deps,
      `set -eu;[ -d '${worker.root}' ];! find '${worker.root}' -maxdepth 1 -type d -name 'probe-*' -print -quit|grep -q .;! pgrep -f -- '${worker.root}/probe-.*/profile' >/dev/null`,
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

async function recoverInterrupted(config, deps) {
  const state = await status(config);
  if (!state.active) return null;
  if (!state.interrupted && state.state !== 'recovery-required')
    throw new ControllerError('another Page Tamper experiment is active', 'OVERLAP', 5);
  const claim = await claimRecovery(config, state, deps);
  const outputs = await validateDeploymentIdentity(config, deps);
  const recovery = await recover(config, deps, outputs);
  const receipt = {
    schema_version: 1,
    run_id: state.run_id,
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
    await preserveRecoveryLock(join(config.receiptDir, 'active.lock'), receipt, error);
    throw new ControllerError('recovery completed but evidence persistence failed', 'EVIDENCE_PERSISTENCE_FAILED', 5);
  }
  if (!recovery.success) throw new ControllerError('interrupted run recovery failed', 'RECOVERY_FAILED', 5);
  await releaseRecoveryClaim(config, claim, deps);
  await rm(join(config.receiptDir, 'active.lock'));
  return receipt;
}

export async function runHeader(config, deps, headerId, options = {}) {
  if (!HEADER_IDS.includes(headerId)) throw new ControllerError(`unsupported header: ${headerId}`, 'INVALID_HEADER', 2);
  const outputs = await validateDeploymentIdentity(config, deps);
  await recoverInterrupted(config, deps);
  const runId = deps.randomUUID();
  const startedAt = deps.now();
  const lockPath = await acquireLock(config, runId, deps.now, 'run');
  let worker = options.worker || null;
  const finalizeWorker = options.finalizeWorker !== false;
  const receipt = {
    schema_version: 1,
    run_id: runId,
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
  const payloads = [];
  try {
    if (!worker && !deps.workerProbe) worker = await prepareWorker(config, deps, runId);
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
      path: PAYMENT_PATH,
      headerId,
      windowStart,
      windowEnd: new Date(deadline).toISOString(),
    };
    receipt.phases.mixed = { required_pairs: config.timings.minimumPairs, completed_pairs: 0, telemetry_valid: true };
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
    receipt.error = { code: error.code || 'INVALID_TEST', message: String(error.message).slice(0, 240) };
    receipt.outcome = 'INVALID_TEST';
  } finally {
    try {
      receipt.recovery = await recover(config, deps, outputs, worker, finalizeWorker);
      if (!receipt.recovery.success) receipt.outcome = 'INVALID_TEST';
    } catch (error) {
      receipt.recovery = {
        success: false,
        error: { code: error.code || 'RECOVERY_FAILED', message: String(error.message).slice(0, 240) },
      };
      receipt.outcome = 'INVALID_TEST';
    }
    receipt.ended_at = deps.now();
    const path = join(config.receiptDir, `${receipt.started_at.replace(/[:.]/g, '-')}-${headerId}-${runId}.json`);
    try {
      await atomicReceipt(path, receipt);
      if (receipt.recovery?.success) await rm(lockPath);
      else await preserveRecoveryLock(lockPath, receipt, new ControllerError('recovery failed', 'RECOVERY_FAILED'));
    } catch (error) {
      await preserveRecoveryLock(lockPath, receipt, error);
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

export async function bootstrap(config, deps) {
  const outputs = await validateDeploymentIdentity(config, deps);
  await recoverInterrupted(config, deps);
  const finder = deps.randomUUID();
  const lockPath = await acquireLock(config, finder, deps.now, 'bootstrap');
  const startedAt = deps.now();
  const receipt = {
    schema_version: 1,
    run_id: finder,
    command: 'bootstrap',
    started_at: startedAt,
    ended_at: null,
    success: false,
    recovery: null,
  };
  let primaryError;
  let finalizationError;
  let worker = null;
  try {
    if (!deps.workerProbe) worker = await prepareWorker(config, deps, finder);
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
    receipt.error = { code: error.code || 'BOOTSTRAP_FAILED', message: String(error.message).slice(0, 240) };
    try {
      receipt.recovery = await recover(config, deps, outputs);
    } catch (recoveryError) {
      receipt.recovery = {
        success: false,
        error: { code: recoveryError.code || 'RECOVERY_FAILED', message: String(recoveryError.message).slice(0, 240) },
      };
    }
  } finally {
    if (worker) {
      const cleanup = await cleanupWorker(config, { ...deps, signal: undefined }, worker);
      if (!cleanup.worker_artifacts_removed) {
        const cleanupError = new ControllerError('worker cleanup failed', 'RECOVERY_FAILED');
        primaryError ||= cleanupError;
        receipt.error ||= { code: cleanupError.code, message: cleanupError.message };
        receipt.success = false;
      }
    }
    receipt.ended_at = deps.now();
    const path = join(config.receiptDir, `bootstrap-${finder}${receipt.success ? '' : '-failed'}.json`);
    try {
      await atomicReceipt(path, receipt);
      if (receipt.success || receipt.recovery?.success) await rm(lockPath);
      else await preserveRecoveryLock(lockPath, receipt, primaryError || new Error('bootstrap recovery failed'));
    } catch (error) {
      await preserveRecoveryLock(lockPath, receipt, error);
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

export async function runSuite(config, deps) {
  const results = [];
  const suiteId = deps.randomUUID();
  const startedAt = deps.now();
  const worker = deps.workerProbe ? null : await prepareWorker(config, deps);
  let cleanup = { worker_artifacts_removed: true };
  let cleanupError = null;
  try {
    for (const headerId of [
      'x-content-type-options',
      ...HEADER_IDS.filter((item) => item !== 'x-content-type-options'),
    ]) {
      const result = await runHeader(config, deps, headerId, { worker, finalizeWorker: false });
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
    try {
      await acquireLock(config, suiteId, deps.now, 'suite-cleanup');
    } catch (error) {
      if (error.code !== 'OVERLAP') throw error;
    }
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
    let ownerDead = false;
    if (lock.hostname === hostname() && Number.isInteger(lock.pid)) {
      try {
        process.kill(lock.pid, 0);
      } catch (error) {
        ownerDead = error.code === 'ESRCH';
      }
    }
    return {
      schema_version: 1,
      active: true,
      state: lock.state || 'active',
      interrupted: persistenceFailure || ownerDead || ageExpired,
      run_id: lock.run_id,
      started_at: lock.started_at,
      cleanup_required: true,
      evidence_persistence_failure: persistenceFailure,
    };
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
    return {
      schema_version: 1,
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
    hostname: overrides.hostname || hostname,
    pid: overrides.pid || (() => process.pid),
    isProcessAlive:
      overrides.isProcessAlive ||
      ((value) => {
        try {
          process.kill(value, 0);
          return true;
        } catch (error) {
          if (error.code === 'ESRCH') return false;
          return true;
        }
      }),
    env: overrides.env || process.env,
    signal: overrides.signal,
    cdp: overrides.cdp,
    probe: overrides.probe,
    workerProbe: overrides.workerProbe,
    alertSource: overrides.alertSource,
    readiness: overrides.readiness,
    cleanup: overrides.cleanup,
    readFile: overrides.readFile || readFile,
    remove: overrides.remove || rm,
    commandTimeoutMs: overrides.commandTimeoutMs || DEFAULT_TIMINGS.commandTimeoutMs,
  };
}
