import { isIP } from 'node:net';
import { SCENARIO_NAMES } from './csd-scenarios.mjs';

export const DEFAULT_TARGET = 'https://client-side-defense.f5-sales-demo.com/';
export const DEFAULT_CDP_ENDPOINT = 'http://127.0.0.1:9222';
export const HELP = `Usage: node scripts/csd-traffic.mjs [options]\n\nModes:\n  --list                     List stable scenarios without connecting to CDP\n  --print-script SCENARIO    Print a canonical browser payload\n  --help                     Print this help\n\nExecution selectors (choose exactly one):\n  --scenario SCENARIO        Run a scenario (repeatable)\n  --all                      Run all scenarios\n\nExecution options:\n  --target HTTPS_URL         Protected target origin (default: ${DEFAULT_TARGET})\n  --allow-host HOSTNAME      Permit an exact additional HTTPS hostname (repeatable)\n  --cdp-endpoint URL         Loopback HTTP or WebSocket CDP endpoint\n  --timeout DURATION         Bounded operation timeout (default: 30s)\n  --settle DURATION          Browser-event collection period (default: 10s)\n  --receipt PATH|-           Atomically write receipt, or emit receipt JSON to stdout\n`;

export class CliError extends Error {
  constructor(message, exitCode = 2, code = 'CLI_ERROR') {
    super(message);
    this.exitCode = exitCode;
    this.code = code;
  }
}

const take = (argv, index, flag) => {
  const value = argv[index + 1];
  if (!value || value.startsWith('--')) throw new CliError(`${flag} requires a value`);
  return value;
};

export function parseDuration(value, flag) {
  const match = /^(\d+(?:\.\d+)?)(ms|s|m)$/.exec(value);
  if (!match) throw new CliError(`${flag} must be a duration such as 500ms, 10s, or 2m`);
  const multiplier = { ms: 1, s: 1_000, m: 60_000 }[match[2]];
  const milliseconds = Number(match[1]) * multiplier;
  if (!Number.isSafeInteger(milliseconds) || milliseconds < (flag === '--settle' ? 0 : 1))
    throw new CliError(`${flag} duration is out of range`);
  return milliseconds;
}

const loopback = (host) => ['localhost', '127.0.0.1', '[::1]', '::1'].includes(host.toLowerCase());

function normalizeAllowedHost(value) {
  if (value.includes('*') || value.includes('/') || value.includes(':') || value.includes('@'))
    throw new CliError('--allow-host must be an exact hostname');
  const host = value.toLowerCase().replace(/\.$/, '');
  if (!host || isIP(host) || !/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(host))
    throw new CliError('--allow-host must be an exact hostname');
  return host;
}

export function sanitizeEndpoint(value) {
  const url = new URL(value);
  url.username = '';
  url.password = '';
  url.search = '';
  url.hash = '';
  return url.href;
}

export function parseArgs(argv) {
  const options = {
    scenarios: [],
    all: false,
    target: DEFAULT_TARGET,
    allowHosts: [],
    cdpEndpoint: DEFAULT_CDP_ENDPOINT,
    timeoutMs: 30_000,
    settleMs: 10_000,
    receipt: null,
    list: false,
    help: false,
    printScript: null,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    if (flag === '--help') options.help = true;
    else if (flag === '--list') options.list = true;
    else if (flag === '--all') options.all = true;
    else if (flag === '--scenario') options.scenarios.push(take(argv, index++, flag));
    else if (flag === '--target') options.target = take(argv, index++, flag);
    else if (flag === '--allow-host') options.allowHosts.push(normalizeAllowedHost(take(argv, index++, flag)));
    else if (flag === '--cdp-endpoint') options.cdpEndpoint = take(argv, index++, flag);
    else if (flag === '--timeout') options.timeoutMs = parseDuration(take(argv, index++, flag), flag);
    else if (flag === '--settle') options.settleMs = parseDuration(take(argv, index++, flag), flag);
    else if (flag === '--receipt') options.receipt = take(argv, index++, flag);
    else if (flag === '--print-script') options.printScript = take(argv, index++, flag);
    else throw new CliError(`unknown option: ${flag}`);
  }
  const modes = [options.help, options.list, Boolean(options.printScript)].filter(Boolean).length;
  const executionSelectors = Number(options.all) + Number(options.scenarios.length > 0);
  if (modes > 1 || (modes && executionSelectors))
    throw new CliError('--help, --list, and --print-script are nonexecution modes and cannot be combined');
  if (!modes && executionSelectors !== 1)
    throw new CliError('exactly one execution selector is required: repeatable --scenario or --all');
  if (options.all && options.scenarios.length) throw new CliError('--all conflicts with --scenario');
  if (new Set(options.scenarios).size !== options.scenarios.length)
    throw new CliError('duplicate --scenario values are not allowed');
  for (const name of options.scenarios)
    if (!SCENARIO_NAMES.includes(name)) throw new CliError(`unknown scenario: ${name}`);
  if (options.printScript && !SCENARIO_NAMES.includes(options.printScript))
    throw new CliError(`unknown scenario: ${options.printScript}`);
  let cdp;
  try {
    cdp = new URL(options.cdpEndpoint);
  } catch {
    throw new CliError('--cdp-endpoint must be a valid URL');
  }
  if (!['http:', 'ws:'].includes(cdp.protocol) || !loopback(cdp.hostname) || cdp.username || cdp.password)
    throw new CliError('--cdp-endpoint must be credential-free loopback HTTP or WebSocket');
  let target;
  try {
    target = new URL(options.target);
  } catch {
    throw new CliError('--target must be a valid URL');
  }
  if (
    target.protocol !== 'https:' ||
    target.username ||
    target.password ||
    (target.port && target.port !== '443') ||
    isIP(target.hostname)
  )
    throw new CliError('--target must be credential-free HTTPS on port 443 with a hostname');
  if (target.pathname !== '/' || target.search || target.hash)
    throw new CliError('--target must be an exact origin with root path; scenarios own routes');
  const allowedHosts = new Set([new URL(DEFAULT_TARGET).hostname, ...options.allowHosts]);
  if (!allowedHosts.has(target.hostname.toLowerCase()))
    throw new CliError(`target host requires exact --allow-host ${target.hostname.toLowerCase()}`);
  if (options.receipt !== null && options.receipt !== '-' && (!options.receipt.trim() || options.receipt.endsWith('/')))
    throw new CliError('--receipt must be a file path or -');
  options.target = target.href;
  options.allowHosts = Object.freeze([...allowedHosts]);
  return Object.freeze(options);
}
