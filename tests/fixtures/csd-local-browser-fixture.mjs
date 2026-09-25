import { execFile, spawn } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import https from 'node:https';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';

import { CdpClient, runScenario } from '../../scripts/lib/csd-runner.mjs';

const execFileAsync = promisify(execFile);
const CHROME_CANDIDATES = Object.freeze([
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  '/Applications/Chromium.app/Contents/MacOS/Chromium',
  '/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary',
]);

async function executable(path) {
  try {
    await execFileAsync('test', ['-x', path]);
    return true;
  } catch {
    return false;
  }
}

async function waitForVersion(port, timeoutMs = 15_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`http://127.0.0.1:${port}/json/version`);
      if (response.ok) return response.json();
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error('local Chrome did not expose CDP before timeout');
}

async function reservePort() {
  const server = https.createServer();
  await new Promise((resolve, reject) => server.listen(0, '127.0.0.1', resolve).once('error', reject));
  const port = server.address().port;
  await new Promise((resolve) => server.close(resolve));
  return port;
}

export async function runLocalBrowserIntegration() {
  const chrome = (
    await Promise.all(CHROME_CANDIDATES.map(async (path) => ((await executable(path)) ? path : null)))
  ).find(Boolean);
  if (!chrome) return { skipped: true, reason: `Chrome/Chromium absent; checked: ${CHROME_CANDIDATES.join(', ')}` };

  const directory = await mkdtemp(join(tmpdir(), 'csd-browser-fixture-'));
  const key = join(directory, 'key.pem');
  const certificate = join(directory, 'certificate.pem');
  const profile = join(directory, 'chrome-profile');
  let server;
  let browser;
  let connection;
  try {
    await writeFile(
      join(directory, 'openssl.cnf'),
      '[req]\ndistinguished_name=dn\nx509_extensions=v3\nprompt=no\n[dn]\nCN=fixture.csd.test\n[v3]\nsubjectAltName=DNS:fixture.csd.test\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n',
    );
    await execFileAsync('openssl', [
      'req',
      '-x509',
      '-newkey',
      'rsa:2048',
      '-nodes',
      '-days',
      '1',
      '-keyout',
      key,
      '-out',
      certificate,
      '-config',
      join(directory, 'openssl.cnf'),
    ]);
    const [keyBytes, certBytes] = await Promise.all([
      import('node:fs/promises').then(({ readFile }) => readFile(key)),
      import('node:fs/promises').then(({ readFile }) => readFile(certificate)),
    ]);
    server = https.createServer({ key: keyBytes, cert: certBytes }, (_request, response) => {
      response.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      response.end(
        '<!doctype html><html><head><script>globalThis.__imp_apg__={fixture:true}</script></head><body><form style="width:320px;height:180px"><input type="email" name="email"><input type="password" name="password"></form></body></html>',
      );
    });
    await new Promise((resolve, reject) => server.listen(0, '127.0.0.1', resolve).once('error', reject));
    const fixturePort = server.address().port;
    const cdpPort = await reservePort();
    browser = spawn(
      chrome,
      [
        '--headless=new',
        '--disable-gpu',
        '--no-first-run',
        '--no-default-browser-check',
        '--ignore-certificate-errors',
        `--remote-debugging-port=${cdpPort}`,
        `--user-data-dir=${profile}`,
        '--host-resolver-rules=MAP fixture.csd.test 127.0.0.1',
        'about:blank',
      ],
      { stdio: 'ignore' },
    );
    const version = await waitForVersion(cdpPort);
    connection = await CdpClient.connect(version.webSocketDebuggerUrl, 5_000, globalThis.WebSocket);
    const target = `https://fixture.csd.test:${fixturePort}/`;
    const receipt = await runScenario('form-overlay', { target, timeoutMs: 10_000, settleMs: 0 }, { cdp: connection });
    return { skipped: false, targetOrigin: `https://fixture.csd.test:${fixturePort}`, receipt };
  } finally {
    connection?.close();
    if (browser) {
      browser.kill('SIGTERM');
      await new Promise((resolve) => browser.once('exit', resolve).once('error', resolve));
    }
    if (server) await new Promise((resolve) => server.close(resolve));
    await rm(directory, { recursive: true, force: true });
  }
}
