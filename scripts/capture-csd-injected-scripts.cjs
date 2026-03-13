// Capture csd-injected-scripts screenshot — connects to DevTools target,
// hides <style> tree items between the three target scripts, captures PNG.
//
// Usage: NODE_PATH=$(npm root -g) node scripts/capture-csd-injected-scripts.cjs <ws-url> <output-path> [theme]
//   theme: "light" (default) or "dark"
//
// Connects to the DevTools WebSocket target (devtools_app.html), queries the
// Elements panel DOM model for the three injected scripts in <head>, hides
// intermediate <style> tree items in the shadow DOM, collapses the Styles
// sidebar and console drawer, then captures a 1280x720 screenshot.

const { WebSocket } = require('ws');
const { writeFileSync } = require('node:fs');

const wsUrl = process.argv[2];
const outputPath = process.argv[3] || '/tmp/csd-injected-scripts-raw.png';
const theme = process.argv[4] || 'light';

if (!wsUrl) {
  console.error('Usage: node capture-csd-injected-scripts.cjs <ws-url> [output-path] [light|dark]');
  process.exit(1);
}

let nextId = 1;
function sendCDP(ws, method, params) {
  const id = nextId++;
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`CDP timeout: ${method}`)), 15000);
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

async function closeDrawer(ws) {
  for (let attempt = 0; attempt < 3; attempt++) {
    const h = await sendCDP(ws, 'Runtime.evaluate', {
      expression: `(function() {
        var d = document.querySelector('.drawer-tabbed-pane');
        if (d) { var r = d.getBoundingClientRect(); return Math.round(r.height); }
        return 0;
      })()`,
      returnByValue: true,
    });
    if ((h?.result?.value || 0) <= 5) break;
    await sendCDP(ws, 'Input.dispatchKeyEvent', {
      type: 'keyDown',
      key: 'Escape',
      code: 'Escape',
      windowsVirtualKeyCode: 27,
      nativeVirtualKeyCode: 27,
    });
    await sendCDP(ws, 'Input.dispatchKeyEvent', {
      type: 'keyUp',
      key: 'Escape',
      code: 'Escape',
      windowsVirtualKeyCode: 27,
      nativeVirtualKeyCode: 27,
    });
    await new Promise((r) => setTimeout(r, 300));
  }
}

const ws = new WebSocket(wsUrl);
ws.on('open', async () => {
  try {
    // 1. Set viewport to 1280x720 at 1x DPR
    await sendCDP(ws, 'Emulation.setDeviceMetricsOverride', {
      width: 1280,
      height: 720,
      deviceScaleFactor: 1,
      mobile: false,
    });

    // 2. Force theme via class on <html> element
    const themeExpr =
      theme === 'dark'
        ? `(function() {
          document.documentElement.classList.add('theme-with-dark-background');
          return document.documentElement.className;
        })()`
        : `(function() {
          document.documentElement.classList.remove('theme-with-dark-background');
          return document.documentElement.className;
        })()`;
    const themeResult = await sendCDP(ws, 'Runtime.evaluate', {
      expression: themeExpr,
      returnByValue: true,
    });
    console.log('Theme classes:', themeResult.result.value);

    // 4. Collapse Styles sidebar
    await sendCDP(ws, 'Runtime.evaluate', {
      expression: 'UI.panels.elements.splitWidget.hideSidebar();',
      returnByValue: true,
    });

    // 5. Close console drawer
    await closeDrawer(ws);

    // 6. Query DOM model for the three target scripts in <head>
    //    Script 1: CSD sync  — <script src="...common.js?single...">
    //    Script 2: Bot Defense — <script src="...bot_defense...">
    //    Script 3: CSD async — <script async ...>
    const queryResult = await sendCDP(ws, 'Runtime.evaluate', {
      expression: `(async function() {
        const to = UI.panels.elements.getTreeOutlineForTesting();
        const dm = to.rootDOMNodeInternal.domModel();
        const doc = await dm.requestDocument();

        // Query each script independently
        const syncIds = await dm.querySelectorAll(doc.id, 'head > script[src*="common.js"]');
        const botIds = await dm.querySelectorAll(doc.id, 'head > script[src*="bot_defense"]');
        const asyncIds = await dm.querySelectorAll(doc.id, 'head > script[async]');

        // Find the sync script that has "single" in src (common.js?single)
        let syncId = null;
        for (const nid of syncIds) {
          const n = dm.nodeForId(nid);
          if (n && n.getAttribute('src') && n.getAttribute('src').includes('single')) {
            syncId = nid;
            break;
          }
        }
        // Fallback: use first common.js script
        if (syncId === null && syncIds.length > 0) syncId = syncIds[0];

        const botId = botIds.length > 0 ? botIds[0] : null;
        const asyncId = asyncIds.length > 0 ? asyncIds[0] : null;

        return JSON.stringify({ syncId, botId, asyncId });
      })()`,
      returnByValue: true,
      awaitPromise: true,
    });

    const ids = JSON.parse(queryResult.result.value);
    console.log('Found script node IDs:', JSON.stringify(ids));

    if (ids.syncId === null || ids.botId === null || ids.asyncId === null) {
      console.error('Could not find all three target scripts');
      console.error('  syncId:', ids.syncId, '  botId:', ids.botId, '  asyncId:', ids.asyncId);
      ws.close();
      process.exit(1);
    }

    // 5. Reveal all three scripts to expand the tree
    for (const nodeId of [ids.syncId, ids.botId, ids.asyncId]) {
      await sendCDP(ws, 'Runtime.evaluate', {
        expression: `(async function() {
          const to = UI.panels.elements.getTreeOutlineForTesting();
          const dm = to.rootDOMNodeInternal.domModel();
          const node = dm.nodeForId(${nodeId});
          await to.revealAndSelectNode(node, true);
        })()`,
        returnByValue: true,
        awaitPromise: true,
      });
      await new Promise((r) => setTimeout(r, 200));
    }

    // 6. Re-hide sidebar (reveal may restore it)
    await sendCDP(ws, 'Runtime.evaluate', {
      expression: 'UI.panels.elements.splitWidget.hideSidebar();',
      returnByValue: true,
    });

    // 7. Re-close drawer
    await closeDrawer(ws);

    // 8. Hide <style> tree items between script 1 and script 3
    const hideResult = await sendCDP(ws, 'Runtime.evaluate', {
      expression: `(function() {
        const to = UI.panels.elements.getTreeOutlineForTesting();
        const items = Array.from(to.shadowRoot.querySelectorAll('li'));
        let hidden = 0;

        // Find the li elements for our three scripts by checking their text content
        let syncLi = null, botLi = null, asyncLi = null;
        let syncIdx = -1, asyncIdx = -1;
        for (let i = 0; i < items.length; i++) {
          const text = items[i].textContent || '';
          if (text.includes('common.js') && text.includes('single') && syncLi === null) {
            syncLi = items[i];
            syncIdx = i;
          }
          if (text.includes('bot_defense') && botLi === null) {
            botLi = items[i];
          }
          if (text.includes('async') && text.includes('script') && asyncLi === null) {
            asyncLi = items[i];
            asyncIdx = i;
          }
        }

        if (syncIdx < 0 || asyncIdx < 0) {
          return JSON.stringify({ error: 'Could not locate script li elements', syncIdx, asyncIdx });
        }

        // Hide all li items between syncLi and asyncLi that contain '<style' text
        for (let i = syncIdx + 1; i < asyncIdx; i++) {
          const text = items[i].textContent || '';
          if (text.includes('<style') || text.includes('style ') || text.includes('style>')) {
            items[i].style.display = 'none';
            hidden++;
          }
        }

        return JSON.stringify({ syncIdx, asyncIdx, hidden });
      })()`,
      returnByValue: true,
    });
    console.log('Hide result:', hideResult.result.value);

    // 9. Scroll script 1 to top of visible area
    await sendCDP(ws, 'Runtime.evaluate', {
      expression: `(function() {
        const to = UI.panels.elements.getTreeOutlineForTesting();
        const items = Array.from(to.shadowRoot.querySelectorAll('li'));
        for (const item of items) {
          const text = item.textContent || '';
          if (text.includes('common.js') && text.includes('single')) {
            item.scrollIntoView({ block: 'start', behavior: 'instant' });
            return 'scrolled';
          }
        }
        return 'not found';
      })()`,
      returnByValue: true,
    });

    // 10. Re-hide sidebar one more time
    await sendCDP(ws, 'Runtime.evaluate', {
      expression: 'UI.panels.elements.splitWidget.hideSidebar();',
      returnByValue: true,
    });

    // Brief delay for tree re-render
    await new Promise((r) => setTimeout(r, 300));

    // 11. Capture screenshot
    const screenshot = await sendCDP(ws, 'Page.captureScreenshot', { format: 'png' });
    if (screenshot?.data) {
      writeFileSync(outputPath, Buffer.from(screenshot.data, 'base64'));
      console.log(`Screenshot saved: ${outputPath}`);
    } else {
      console.error('Screenshot capture failed');
      ws.close();
      process.exit(1);
    }

    ws.close();
    process.exit(0);
  } catch (err) {
    console.error('Error:', err.message);
    ws.close();
    process.exit(1);
  }
});

ws.on('error', (e) => {
  console.error('WebSocket error:', e.message);
  process.exit(1);
});

setTimeout(() => {
  console.error('Timeout (30s)');
  ws.close();
  process.exit(1);
}, 30000);
