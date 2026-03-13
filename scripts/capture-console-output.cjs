// Capture Console panel screenshot — optionally runs an attack script via the
// DevTools Console prompt API before capturing.
//
// Usage: NODE_PATH=$(npm root -g) node scripts/capture-console-output.cjs \
//          <page-ws-url> <devtools-ws-url> <script-file|""> <output-path> [theme]
//
// Pass "" as <script-file> to capture a clean (empty) Console panel.

const { WebSocket } = require('ws');
const { writeFileSync, readFileSync } = require('node:fs');

const pageWsUrl = process.argv[2];
const devtoolsWsUrl = process.argv[3];
const scriptFile = process.argv[4];
const outputPath = process.argv[5] || '/tmp/console-output.png';
const theme = process.argv[6] || 'light';

if (!pageWsUrl || !devtoolsWsUrl) {
  console.error(
    'Usage: node capture-console-output.cjs <page-ws> <devtools-ws> <script-file|""> <output-path> [light|dark]',
  );
  process.exit(1);
}

const attackScript = scriptFile ? readFileSync(scriptFile, 'utf8') : null;

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

    // --- DevTools target: suppress errors and clear console ---
    // The demo site fires error-level messages (common.js runtime errors,
    // Bot Defense WebSocket reconnection failures) that pollute Console
    // screenshots. Temporarily hiding error/warning levels before clearing
    // ensures any late-arriving errors are suppressed, then resetting the
    // filter restores the toolbar to "Default levels" with 0 hidden.
    console.log('Suppressing error/warning levels...');
    await dt.sendCDP('Runtime.evaluate', {
      expression: `(function() {
        var f = UI.panels.console.view.filter;
        f.messageLevelFiltersSetting.set({verbose: false, info: true, warning: false, error: false});
        return 'errors suppressed';
      })()`,
      returnByValue: true,
    });

    console.log('Clearing console...');
    await dt.sendCDP('Runtime.evaluate', {
      expression: 'UI.panels.console.view.clearConsole()',
      returnByValue: true,
    });
    await sleep(500);

    // --- DevTools target: execute attack script (if provided) ---
    // Keep error/warning filter active during execution so errors from
    // injected CDN scripts never register as visible messages.
    if (attackScript) {
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
    } else {
      console.log('No script file — capturing clean console.');
    }

    // Restore default level filters now that errors have been suppressed.
    // This resets the toolbar label from "Info only" to "Default levels".
    console.log('Restoring default level filters...');
    await dt.sendCDP('Runtime.evaluate', {
      expression: `(function() {
        var f = UI.panels.console.view.filter;
        f.messageLevelFiltersSetting.set({verbose: false, info: true, warning: true, error: true});
        return 'filters restored';
      })()`,
      returnByValue: true,
    });

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

    // --- DevTools target: hide error/issue badges ---
    // The demo site and injected CDN scripts trigger Chrome Issues (CORS,
    // module errors) that produce counters in both the main toolbar and
    // the Console toolbar. These are separate from Console message levels
    // and must be hidden via DOM manipulation.
    console.log('Hiding error/issue badges...');
    await dt.sendCDP('Runtime.evaluate', {
      expression: `(function() {
        var hidden = [];
        // Hide counters in the main toolbar (inside shadow DOM)
        var pane = document.querySelector('.main-tabbed-pane');
        if (pane && pane.shadowRoot) {
          var rt = pane.shadowRoot.querySelector('.tabbed-pane-right-toolbar');
          if (rt) {
            var ib = rt.querySelector('icon-button');
            if (ib) { ib.style.display = 'none'; hidden.push('error-counter'); }
            var ic = rt.querySelector('devtools-issue-counter');
            if (ic) { ic.style.display = 'none'; hidden.push('issue-counter-top'); }
          }
        }
        // Hide issue counter in the Console toolbar
        var ci = document.querySelector('devtools-issue-counter');
        if (ci) { ci.style.display = 'none'; hidden.push('issue-counter-console'); }
        return hidden.join(',');
      })()`,
      returnByValue: true,
    });

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
