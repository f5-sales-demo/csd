// CDP interact script — opens Command Menu, types a command, screenshots the result.
// Usage: NODE_PATH=$(npm root -g) node scripts/cdp-interact.cjs <ws-url> <command> <output-path>
//
// Extracted from SCREENSHOT-INSTRUCTIONS.md Example B.
// Sets Emulation.setDeviceMetricsOverride to 1280x720 at 1x DPR before capture.
//
// WARNING: document.dispatchEvent(KeyboardEvent) does NOT reliably open the
// DevTools Command Menu. DevTools keyboard shortcuts are handled above the DOM
// event layer. Prefer setting the panel via `panel-selected-tab` preference
// (Section 3 of SCREENSHOT-INSTRUCTIONS.md) and restarting Chrome. This script
// is a best-effort fallback.

const { WebSocket } = require('ws');
const { writeFileSync } = require('node:fs');

const wsUrl = process.argv[2];
const command = process.argv[3];
const outputPath = process.argv[4];

if (!wsUrl || !command || !outputPath) {
  console.error('Usage: node cdp-interact.cjs <ws-url> <command> <output-path>');
  process.exit(1);
}

let nextId = 1;
function sendCDP(ws, method, params) {
  const id = nextId++;
  return new Promise((resolve) => {
    const handler = (data) => {
      const msg = JSON.parse(data.toString());
      if (msg.id === id) {
        ws.removeListener('message', handler);
        resolve(msg.result);
      }
    };
    ws.on('message', handler);
    ws.send(JSON.stringify({ id, method, params }));
  });
}

// Poll for a condition by evaluating an expression on the DevTools target.
// Returns when the expression returns a truthy value, or after maxAttempts.
async function pollFor(ws, expression, { maxAttempts = 20, intervalMs = 250 } = {}) {
  for (let i = 0; i < maxAttempts; i++) {
    const result = await sendCDP(ws, 'Runtime.evaluate', {
      expression,
      returnByValue: true,
    });
    if (result?.result?.value) {
      return result.result.value;
    }
    await new Promise((r) => setTimeout(r, intervalMs));
  }
  return null;
}

const ws = new WebSocket(wsUrl);
ws.on('open', async () => {
  // Set viewport to exact 1280x720 at 1x DPR
  await sendCDP(ws, 'Emulation.setDeviceMetricsOverride', {
    width: 1280,
    height: 720,
    deviceScaleFactor: 1,
    mobile: false,
  });

  // Open Command Menu (Cmd+Shift+P) — best-effort, see WARNING above
  await sendCDP(ws, 'Runtime.evaluate', {
    expression: `document.dispatchEvent(new KeyboardEvent('keydown', {
            key: 'P', code: 'KeyP', metaKey: true, shiftKey: true,
            bubbles: true, cancelable: true
        }));`,
    returnByValue: true,
  });

  // Poll for the command palette to appear (max 5s)
  await pollFor(
    ws,
    `(function() {
        var el = document.querySelector('.command-palette, [class*="CommandMenu"], .filtered-list-widget');
        return el ? true : false;
    })()`,
    { maxAttempts: 20, intervalMs: 250 },
  );

  // Type the command
  await sendCDP(ws, 'Input.insertText', { text: command });

  // Brief pause for autocomplete to settle
  await new Promise((r) => setTimeout(r, 300));

  // Press Enter
  await sendCDP(ws, 'Input.dispatchKeyEvent', {
    type: 'keyDown',
    key: 'Enter',
    code: 'Enter',
    windowsVirtualKeyCode: 13,
  });
  await sendCDP(ws, 'Input.dispatchKeyEvent', {
    type: 'keyUp',
    key: 'Enter',
    code: 'Enter',
    windowsVirtualKeyCode: 13,
  });

  // Poll for the panel switch to complete (check that command palette is gone)
  await pollFor(
    ws,
    `(function() {
        var el = document.querySelector('.command-palette, [class*="CommandMenu"], .filtered-list-widget');
        return el ? false : true;
    })()`,
    { maxAttempts: 20, intervalMs: 250 },
  );

  // Take screenshot
  const result = await sendCDP(ws, 'Page.captureScreenshot', { format: 'png' });
  if (result?.data) {
    writeFileSync(outputPath, Buffer.from(result.data, 'base64'));
    console.log(`Screenshot saved: ${outputPath}`);
  }

  ws.close();
  process.exit(0);
});

ws.on('error', (e) => {
  console.error(e.message);
  process.exit(1);
});
setTimeout(() => {
  console.error('Timeout');
  ws.close();
  process.exit(1);
}, 15000);
