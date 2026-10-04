#!/usr/bin/env node
import { lstat, open } from 'node:fs/promises';
import { isAbsolute, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { CdpClient, CliError, runDocumentProbe, withAbort } from './lib/csd-runner.mjs';

export const TARGET = 'https://client-side-defense.f5-sales-demo.com/csd-page-tamper/payment';
export const CLEANUP_GRACE_MS = 1000;
export const HELP = `Usage: node scripts/csd-header-visibility.mjs --cdp-endpoint http://127.0.0.1:PORT --expected-profile /absolute/owned/profile [--timeout-ms 30000] [--settle-ms 5000] [--artifact /private/receipt.json]
Observe exactly one control then one x-content-type-options omission in fresh contexts.
No collector semantic acceptance, baseline eligibility, or CSD alert inference.
`;
const fail = (code) => new CliError(code, 2, code);
const bounds = (options) => {
  const timeoutMs = options.timeoutMs ?? 30000;
  const settleMs = options.settleMs ?? 5000;
  if (
    !Number.isSafeInteger(timeoutMs) ||
    timeoutMs < 1 ||
    timeoutMs > 30000 ||
    !Number.isSafeInteger(settleMs) ||
    settleMs < 0 ||
    settleMs > 15000
  )
    throw fail('INVALID_TIMING');
  if (
    typeof options.expectedProfile !== 'string' ||
    !isAbsolute(options.expectedProfile) ||
    resolve(options.expectedProfile) !== options.expectedProfile
  )
    throw fail('PROFILE_REQUIRED');
  return { ...options, timeoutMs, settleMs };
};
export function parseArgs(argv) {
  if (argv.length === 1 && argv[0] === '--help') return { help: true };
  const names = {
    '--cdp-endpoint': 'cdpEndpoint',
    '--expected-profile': 'expectedProfile',
    '--timeout-ms': 'timeoutMs',
    '--settle-ms': 'settleMs',
    '--artifact': 'artifact',
  };
  const options = {};
  for (let i = 0; i < argv.length; i += 2) {
    const key = names[argv[i]];
    if (!key || options[key] !== undefined || !argv[i + 1]) throw fail('INVALID_ARGUMENT');
    options[key] = ['timeoutMs', 'settleMs'].includes(key) ? Number(argv[i + 1]) : argv[i + 1];
  }
  const result = bounds(options);
  let endpoint;
  try {
    endpoint = new URL(result.cdpEndpoint);
  } catch {
    throw fail('INVALID_ENDPOINT');
  }
  if (
    endpoint.protocol !== 'http:' ||
    endpoint.hostname !== '127.0.0.1' ||
    !endpoint.port ||
    endpoint.pathname !== '/' ||
    endpoint.search ||
    endpoint.hash ||
    endpoint.username ||
    endpoint.password
  )
    throw fail('INVALID_ENDPOINT');
  if (result.artifact && !isAbsolute(result.artifact)) throw fail('INVALID_ARTIFACT');
  return result;
}

// Product and argv are verified in memory, never included in the public receipt.
export async function runBoundedPair(input, deps) {
  const options = bounds(input);
  if (!deps?.cdp) throw fail('CDP_REQUIRED');
  const abort = new AbortController();
  const forward = () => abort.abort();
  deps.signal?.addEventListener('abort', forward, { once: true });
  if (deps.signal?.aborted) abort.abort();
  const deadline = Date.now() + options.timeoutMs;
  const timer = setTimeout(forward, options.timeoutMs);
  const receipt = {
    schema_version: 1,
    mode: 'header-visibility-pair',
    target: TARGET,
    browser_provenance: null,
    observations: [],
    success: false,
    collector_semantic_acceptance: 'not-observed',
  };
  receipt.timing = { observation_timeout_ms: options.timeoutMs, cleanup_grace_ms: CLEANUP_GRACE_MS };
  const cdp = {
    onEvent: (listener) => deps.cdp.onEvent?.(listener),
    send: (method, params, sessionId, { signal = abort.signal } = {}) =>
      withAbort(() => deps.cdp.send(method, params, sessionId, { signal }), signal),
  };
  try {
    const info = await cdp.send('Browser.getBrowserCommandLine');
    const version = await cdp.send('Browser.getVersion');
    const args = info.arguments;
    if (
      !Array.isArray(args) ||
      !args.every((arg) => typeof arg === 'string') ||
      args.some((arg) =>
        [
          '--headless',
          '--no-sandbox',
          '--disable-setuid-sandbox',
          '--disable-gpu-sandbox',
          '--disable-seccomp-filter-sandbox',
          '--single-process',
          '--in-process-gpu',
        ].some((flag) => arg === flag || arg.startsWith(`${flag}=`)),
      ) ||
      args.filter((arg) => arg.startsWith('--user-data-dir')).length !== 1 ||
      !args.includes(`--user-data-dir=${options.expectedProfile}`) ||
      !args.includes('--enable-automation') ||
      !args.includes('--remote-debugging-address=127.0.0.1') ||
      !/^Chrome\/\d+(?:\.\d+){3}$/.test(version.product || '')
    )
      throw fail('BROWSER_PROVENANCE_FAILED');
    const stat = await withAbort(() => (deps.lstat || lstat)(options.expectedProfile), abort.signal);
    if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== process.getuid?.())
      throw fail('PROFILE_NOT_OWNED');
    receipt.browser_provenance = {
      headed_arguments_verified: true,
      chrome_product_verified: true,
      sandbox_disable_flags_absent: true,
      owned_profile_verified: true,
    };
    for (const selector of [undefined, 'x-content-type-options']) {
      if (abort.signal.aborted || Date.now() >= deadline) throw fail('PAIR_TIMEOUT');
      const observation = await runDocumentProbe(
        {
          target: TARGET,
          ...(selector ? { selector } : {}),
          timeoutMs: Math.max(1, deadline - Date.now()),
          settleMs: options.settleMs,
        },
        { cdp, captureMetadata: true, signal: abort.signal, cleanupGraceMs: CLEANUP_GRACE_MS },
      );
      receipt.observations.push(observation);
      if (observation.cleanup.failed) break;
    }
    receipt.success = receipt.observations.length === 2 && receipt.observations.every(({ success }) => success);
  } catch (error) {
    receipt.error = {
      code: abort.signal.aborted
        ? 'PAIR_TIMEOUT'
        : ['BROWSER_PROVENANCE_FAILED', 'PROFILE_NOT_OWNED'].includes(error.code)
          ? error.code
          : 'PAIR_FAILED',
    };
  } finally {
    clearTimeout(timer);
    deps.signal?.removeEventListener('abort', forward);
    const closeAbort = new AbortController();
    const closeTimer = setTimeout(() => closeAbort.abort(), CLEANUP_GRACE_MS);
    try {
      await withAbort(() => deps.cdp.close(), closeAbort.signal);
      receipt.client_closed = true;
    } catch {
      receipt.client_closed = false;
      receipt.success = false;
      receipt.error ??= { code: 'CLEANUP_FAILED' };
    } finally {
      clearTimeout(closeTimer);
    }
  }
  return receipt;
}

export async function main(argv = process.argv.slice(2), deps = {}) {
  const stdout = deps.stdout || process.stdout;
  let cdp;
  let receipt;
  let options;
  const abort = new AbortController();
  const handlers = ['SIGINT', 'SIGTERM'].map((name) => {
    const handler = () => abort.abort();
    process.once(name, handler);
    return [name, handler];
  });
  try {
    options = parseArgs(argv);
    if (options.help) {
      stdout.write(HELP);
      return 0;
    }
    const fetchImpl = deps.fetch || globalThis.fetch;
    const response = await fetchImpl(new URL('/json/version', options.cdpEndpoint), {
      signal: AbortSignal.any([abort.signal, AbortSignal.timeout(options.timeoutMs)]),
    });
    if (!response.ok) throw fail('DISCOVERY_FAILED');
    const info = await response.json();
    const ws = new URL(info.webSocketDebuggerUrl);
    if (
      ws.protocol !== 'ws:' ||
      ws.hostname !== '127.0.0.1' ||
      ws.port !== new URL(options.cdpEndpoint).port ||
      ws.username ||
      ws.password ||
      ws.search ||
      ws.hash ||
      !/^\/devtools\/browser\/[a-zA-Z0-9-]+$/.test(ws.pathname)
    )
      throw fail('DISCOVERY_UNSAFE');
    cdp =
      deps.cdp ||
      (await CdpClient.connect(
        ws.href,
        Math.min(options.timeoutMs, 1000),
        deps.WebSocket || globalThis.WebSocket,
        abort.signal,
      ));
    receipt = await runBoundedPair(options, { ...deps, cdp, signal: abort.signal });
    cdp = null; // Pair owns the client and closes it, including provenance failures.
    if (options.artifact) {
      const handle = await open(options.artifact, 'wx', 0o600);
      try {
        await handle.writeFile(`${JSON.stringify(receipt)}\n`);
        await handle.sync();
      } finally {
        await handle.close();
      }
    }
  } catch {
    receipt = receipt
      ? { ...receipt, success: false, error: { code: 'ARTIFACT_WRITE_FAILED' } }
      : { schema_version: 1, mode: 'header-visibility-pair', success: false, error: { code: 'ENTRY_FAILED' } };
  } finally {
    cdp?.close();
    for (const [name, handler] of handlers) process.removeListener(name, handler);
  }
  stdout.write(`XCSH_RESULT ${JSON.stringify(receipt)}\n`);
  return receipt.success ? 0 : 4;
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href)
  process.exitCode = await main();
