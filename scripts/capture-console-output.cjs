// Capture console output screenshot — runs attack script via DevTools Console
// prompt API, then captures the Console panel screenshot.
//
// Usage: NODE_PATH=$(npm root -g) node scripts/capture-console-output.cjs \
//          <page-ws-url> <devtools-ws-url> <script-file> <output-path> [theme]

const { WebSocket } = require('ws');
const { writeFileSync, readFileSync } = require('node:fs');

const pageWsUrl = process.argv[2];
const devtoolsWsUrl = process.argv[3];
const scriptFile = process.argv[4];
const outputPath = process.argv[5] || '/tmp/console-output.png';
const theme = process.argv[6] || 'light';

if (!pageWsUrl || !devtoolsWsUrl || !scriptFile) {
  console.error(
    'Usage: node capture-console-output.cjs <page-ws> <devtools-ws> <script-file> <output-path> [light|dark]',
  );
  process.exit(1);
}

const attackScript = readFileSync(scriptFile, 'utf8');

function createCDP(wsUrl, label) {
  let nextId = 1;
  const ws = new WebSocket(wsUrl);

  function sendCDP(method, params) {
    const id = nextId++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error(`CDP timeout: ${method} on ${label}`)), 15000);
      const handler = (data) => {
        const msg = JSON.parse(data.toString());
        if (msg.id === id) {
          ws.removeListener('message', handler);
          clearTimeout(timer);
          resolve(msg.result);
        }
      };
      ws.on('message', handler);
      ws.send(JSON.stringify({ id, method, params }));
    });
  }

  return new Promise((resolve, reject) => {
    ws.on('open', () => resolve({ ws, sendCDP }));
    ws.on('error', (e) => reject(new Error(`${label} WS error: ${e.message}`)));
    setTimeout(() => reject(new Error(`${label} connection timeout`)), 10000);
  });
}

async function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

(async () => {
  try {
    console.log('Connecting to page target...');
    const page = await createCDP(pageWsUrl, 'page');
    console.log('Connecting to DevTools target...');
    const dt = await createCDP(devtoolsWsUrl, 'devtools');

    // --- Page target: dismiss cookie banner ---
    console.log('Dismissing cookie banner...');
    await page.sendCDP('Runtime.evaluate', {
      expression: `(function() {
        var btn = document.querySelector('.cc-dismiss, [aria-label="dismiss cookie message"], .cc-btn');
        if (btn) { btn.click(); return 'dismissed'; }
        return 'no banner';
      })()`,
      returnByValue: true,
    });
    await sleep(500);

    // --- Page target: fill credentials ---
    console.log('Filling credentials...');
    await page.sendCDP('Runtime.evaluate', {
      expression: `(function() {
        var email = document.querySelector('input[name="email"], input[type="email"], #email');
        if (email) { email.focus(); email.value = 'test@example.com'; email.dispatchEvent(new Event('input', {bubbles:true})); }
        var pw = document.querySelector('input[name="password"], input[type="password"], #password');
        if (pw) { pw.focus(); pw.value = 'P@ssword123'; pw.dispatchEvent(new Event('input', {bubbles:true})); }
        return 'done';
      })()`,
      returnByValue: true,
    });
    await sleep(300);

    // --- DevTools target: set viewport ---
    console.log('Setting DevTools viewport to 1280x720...');
    await dt.sendCDP('Emulation.setDeviceMetricsOverride', {
      width: 1280,
      height: 720,
      deviceScaleFactor: 1,
      mobile: false,
    });

    // --- DevTools target: force theme ---
    console.log(`Forcing ${theme} theme...`);
    const themeExpr =
      theme === 'dark'
        ? `document.documentElement.classList.add('theme-with-dark-background')`
        : `document.documentElement.classList.remove('theme-with-dark-background')`;
    await dt.sendCDP('Runtime.evaluate', { expression: themeExpr, returnByValue: true });

    // --- DevTools target: clear console ---
    console.log('Clearing console...');
    await dt.sendCDP('Runtime.evaluate', {
      expression: 'UI.panels.console.view.clearConsole()',
      returnByValue: true,
    });
    await sleep(500);

    // --- DevTools target: execute attack script via prompt.appendCommand ---
    console.log('Executing attack script via Console prompt...');
    const escapedScript = JSON.stringify(attackScript);
    const evalResult = await dt.sendCDP('Runtime.evaluate', {
      expression: `(function() {
        var prompt = UI.panels.console.view.prompt;
        prompt.appendCommand(${escapedScript}, true);
        return 'command submitted';
      })()`,
      returnByValue: true,
    });
    console.log('Eval result:', evalResult?.result?.value);

    // Wait for script execution + async callbacks (script loads, fetches)
    console.log('Waiting for async callbacks...');
    await sleep(6000);

    // --- Check message count ---
    const msgCount = await dt.sendCDP('Runtime.evaluate', {
      expression: `document.querySelectorAll('.console-message-wrapper').length`,
      returnByValue: true,
    });
    console.log('Visible console messages:', msgCount?.result?.value);

    // --- DevTools target: close Console drawer if open ---
    // Press Escape to close the drawer
    await dt.sendCDP('Input.dispatchKeyEvent', {
      type: 'keyDown',
      key: 'Escape',
      code: 'Escape',
      windowsVirtualKeyCode: 27,
    });
    await dt.sendCDP('Input.dispatchKeyEvent', {
      type: 'keyUp',
      key: 'Escape',
      code: 'Escape',
      windowsVirtualKeyCode: 27,
    });
    await sleep(300);

    // --- DevTools target: scroll to bottom ---
    console.log('Scrolling to bottom...');
    await dt.sendCDP('Runtime.evaluate', {
      expression: 'UI.panels.console.view.immediatelyScrollToBottom()',
      returnByValue: true,
    });
    await sleep(500);

    // --- Capture ---
    console.log('Capturing screenshot...');
    const screenshot = await dt.sendCDP('Page.captureScreenshot', { format: 'png' });
    if (screenshot?.data) {
      writeFileSync(outputPath, Buffer.from(screenshot.data, 'base64'));
      console.log(`Screenshot saved: ${outputPath}`);
    } else {
      console.error('Screenshot capture failed');
      process.exit(1);
    }

    page.ws.close();
    dt.ws.close();
    process.exit(0);
  } catch (err) {
    console.error('Error:', err.message);
    process.exit(1);
  }
})();
