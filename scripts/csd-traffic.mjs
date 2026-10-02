#!/usr/bin/env node

import { pathToFileURL } from 'node:url';
import { main } from './lib/csd-runner.mjs';

export { CdpClient, CliError, main, parseArgs, runDocumentProbe, runScenario } from './lib/csd-runner.mjs';

if (import.meta.url === pathToFileURL(process.argv[1] || '').href) process.exitCode = await main();
