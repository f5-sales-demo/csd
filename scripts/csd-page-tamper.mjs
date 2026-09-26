#!/usr/bin/env node

import { pathToFileURL } from 'node:url';
import {
  bootstrap,
  ControllerError,
  createDependencies,
  DEFAULT_TIMINGS,
  HEADER_IDS,
  PAYMENT_PATH,
  runHeader,
  runSuite,
  status,
} from './lib/csd-page-tamper-controller.mjs';

const DEFAULT_TARGET = `https://client-side-defense.f5-sales-demo.com${PAYMENT_PATH}`;
export const HELP = `Usage: node scripts/csd-page-tamper.mjs <bootstrap|run|suite|status> [options]

Commands:
  bootstrap                  Validate identity, no drift, readiness, browsers, and baseline
  run --header HEADER_ID     Execute one bounded mixed-cohort experiment
  suite                      Run XCTO canary, then all remaining headers after canary success
  status                     Report active or interrupted run state without exposing identities

Required options (or matching environment variables):
  --target URL               XCSH_CSD_PAGE_TAMPER_TARGET
  --aws-profile NAME         AWS_PROFILE
  --aws-region REGION        AWS_REGION
  --aws-account ID           XCSH_CSD_AWS_ACCOUNT
  --worker-instance ID       XCSH_CSD_WORKER_INSTANCE
  --terraform-dir PATH       XCSH_CSD_TERRAFORM_DIR
  --f5-api-url URL           XCSH_API_URL
  XCSH_API_TOKEN             Required environment-only F5 API token (never printed or persisted)
  --namespace NAME           XCSH_NAMESPACE
  --lb-name NAME             XCSH_LB_NAME
  --receipt-dir PATH         XCSH_CSD_PAGE_TAMPER_RECEIPT_DIR
  --cdp-endpoint URL         XCSH_CDP_ENDPOINT (loopback; default http://127.0.0.1:9222)

Production timing defaults: 45m bootstrap, 15m reinforcement, 45m mixed,
60s alert polling, 15m recovery, 12 reinforcement profiles, 20 mixed pairs,
and a 90m hard case deadline. Timing overrides are programmatic test inputs only.

Header IDs:
  ${HEADER_IDS.join('\n  ')}
`;

const OPTION_NAMES = new Map([
  ['--target', 'target'],
  ['--aws-profile', 'awsProfile'],
  ['--aws-region', 'awsRegion'],
  ['--aws-account', 'awsAccount'],
  ['--worker-instance', 'workerInstance'],
  ['--terraform-dir', 'terraformDir'],
  ['--f5-api-url', 'f5ApiUrl'],
  ['--namespace', 'namespace'],
  ['--lb-name', 'lbName'],
  ['--receipt-dir', 'receiptDir'],
  ['--cdp-endpoint', 'cdpEndpoint'],
  ['--header', 'header'],
]);

export function parseArgs(argv, env = process.env) {
  if (argv.includes('--help') || argv.includes('-h')) return { help: true };
  const command = argv[0];
  if (!['bootstrap', 'run', 'suite', 'status'].includes(command))
    throw new ControllerError('choose bootstrap, run, suite, or status', 'CLI_ERROR', 2);
  const values = {};
  for (let index = 1; index < argv.length; index += 2) {
    const name = argv[index];
    if (!OPTION_NAMES.has(name)) throw new ControllerError(`unknown option: ${name}`, 'CLI_ERROR', 2);
    if (argv[index + 1] === undefined || argv[index + 1].startsWith('--'))
      throw new ControllerError(`${name} requires a value`, 'CLI_ERROR', 2);
    values[OPTION_NAMES.get(name)] = argv[index + 1];
  }
  const config = {
    target: values.target || env.XCSH_CSD_PAGE_TAMPER_TARGET || DEFAULT_TARGET,
    awsProfile: values.awsProfile || env.AWS_PROFILE,
    awsRegion: values.awsRegion || env.AWS_REGION,
    awsAccount: values.awsAccount || env.XCSH_CSD_AWS_ACCOUNT,
    workerInstance: values.workerInstance || env.XCSH_CSD_WORKER_INSTANCE,
    terraformDir: values.terraformDir || env.XCSH_CSD_TERRAFORM_DIR,
    f5ApiUrl: values.f5ApiUrl || env.XCSH_API_URL,
    f5ApiToken: env.XCSH_API_TOKEN,
    namespace: values.namespace || env.XCSH_NAMESPACE,
    lbName: values.lbName || env.XCSH_LB_NAME,
    receiptDir: values.receiptDir || env.XCSH_CSD_PAGE_TAMPER_RECEIPT_DIR,
    cdpEndpoint: values.cdpEndpoint || env.XCSH_CDP_ENDPOINT || 'http://127.0.0.1:9222',
    probeTimeoutMs: 30_000,
    probeSettleMs: 10_000,
    timings: { ...DEFAULT_TIMINGS },
  };
  const required =
    command === 'status'
      ? ['receiptDir']
      : [
          'awsProfile',
          'awsRegion',
          'awsAccount',
          'workerInstance',
          'terraformDir',
          'f5ApiUrl',
          'f5ApiToken',
          'namespace',
          'lbName',
          'receiptDir',
        ];
  for (const name of required)
    if (!config[name]) throw new ControllerError(`missing required configuration: ${name}`, 'CLI_ERROR', 2);
  if (command === 'run' && !values.header) throw new ControllerError('run requires --header', 'CLI_ERROR', 2);
  if (values.header && !HEADER_IDS.includes(values.header))
    throw new ControllerError(`unsupported header: ${values.header}`, 'CLI_ERROR', 2);
  return { command, header: values.header, config };
}

export async function main(argv = process.argv.slice(2), overrides = {}) {
  const stdout = overrides.stdout || process.stdout;
  const stderr = overrides.stderr || process.stderr;
  const abortController = overrides.abortController || new AbortController();
  const handlers = new Map();
  if (!overrides.signal) {
    for (const name of ['SIGINT', 'SIGTERM']) {
      const handler = () => abortController.abort(new ControllerError(`received ${name}`, 'INTERRUPTED'));
      handlers.set(name, handler);
      process.once(name, handler);
    }
  }
  try {
    const parsed = parseArgs(argv, overrides.env || process.env);
    if (parsed.help) {
      stdout.write(HELP);
      return 0;
    }
    const deps = createDependencies({ ...overrides, signal: overrides.signal || abortController.signal });
    let result;
    if (parsed.command === 'bootstrap') result = await bootstrap(parsed.config, deps);
    if (parsed.command === 'run') result = await runHeader(parsed.config, deps, parsed.header);
    if (parsed.command === 'suite') result = await runSuite(parsed.config, deps);
    if (parsed.command === 'status') result = await status(parsed.config);
    stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    return result?.success === false || result?.outcome === 'INVALID_TEST' ? 4 : 0;
  } catch (error) {
    const known =
      error instanceof ControllerError
        ? error
        : new ControllerError(error.message || String(error), 'UNEXPECTED_ERROR', 1);
    stderr.write(`${JSON.stringify({ error: { code: known.code, message: known.message } })}\n`);
    return known.exitCode;
  } finally {
    for (const [name, handler] of handlers) process.removeListener(name, handler);
  }
}

if (import.meta.url === pathToFileURL(process.argv[1] || '').href) process.exitCode = await main();
