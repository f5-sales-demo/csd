const { readFileSync, writeFileSync } = require('node:fs');
const { resolve } = require('node:path');
const { WebSocket } = require('ws');

// Parse args: node annotate-screenshot.cjs <screenshot> <output> <width> <height> <badges-json>
const [, , screenshotPath, outputPath, width, height, badgesJson] = process.argv;

if (!screenshotPath || !outputPath || !badgesJson) {
  console.error(`Usage: node annotate-screenshot.cjs <screenshot> <output> <width> <height> '<badges-json>'`);
  console.error(`  badges-json: [{"text":"Label","class":"badge-csd","centerY":110,"left":500}, ...]`);
  console.error(`  Available classes: badge-csd, badge-thirdparty, badge-info, badge-warning, badge-success`);
  process.exit(1);
}

const w = parseInt(width, 10) || 1600;
const h = parseInt(height, 10) || 900;
const badges = JSON.parse(badgesJson);

// Build HTML
let template = readFileSync('scripts/annotate-template.html', 'utf8');
template = template.replace('BODY_WIDTH', w);
template = template.replace('BODY_HEIGHT', h);
template = template.replace('SCREENSHOT_PATH', `file://${resolve(screenshotPath)}`);

const badgeHtml = badges
  .map((b) => {
    const cls = b.class || 'badge-thirdparty';
    const useCenterY = b.centerY != null;
    const yValue = useCenterY ? b.centerY : b.top;
    const centerCls = useCenterY ? ' badge-centered' : '';
    const style = `top: ${yValue}px; left: ${b.left}px;${b.style || ''}`;
    return `  <div class="badge ${cls}${centerCls}" style="${style}">${b.text}</div>`;
  })
  .join('\n');

template = template.replace('<!-- BADGES_PLACEHOLDER -->', badgeHtml);

const tmpHtml = '/tmp/annotate-render.html';
writeFileSync(tmpHtml, template);

// Connect to Chrome CDP and render
async function main() {
  const resp = await fetch('http://localhost:9222/json');
  const targets = await resp.json();
  const target = targets.find((t) => t.type === 'page' && !t.url.includes('devtools'));
  if (!target) {
    console.error('No page target found');
    process.exit(1);
  }

  const ws = new WebSocket(target.webSocketDebuggerUrl);
  let nextId = 1;

  function send(method, params) {
    const msgId = nextId++;
    return new Promise((resolve, reject) => {
      const handler = (data) => {
        const msg = JSON.parse(data.toString());
        if (msg.id === msgId) {
          ws.removeListener('message', handler);
          resolve(msg.result);
        }
      };
      ws.on('message', handler);
      ws.send(JSON.stringify({ id: msgId, method, params }));
      setTimeout(() => reject(new Error('Timeout')), 10000);
    });
  }

  ws.on('open', async () => {
    try {
      // Set viewport
      await send('Emulation.setDeviceMetricsOverride', {
        width: w,
        height: h,
        deviceScaleFactor: 1,
        mobile: false,
      });

      // Navigate
      await send('Page.navigate', { url: `file://${tmpHtml}` });
      await new Promise((r) => setTimeout(r, 2000));

      // Capture
      const result = await send('Page.captureScreenshot', {
        format: 'png',
        clip: { x: 0, y: 0, width: w, height: h, scale: 1 },
      });

      if (result?.data) {
        writeFileSync(outputPath, Buffer.from(result.data, 'base64'));
        console.log(`Annotated screenshot saved: ${outputPath} (${w}x${h})`);
      }

      // Reset viewport
      await send('Emulation.clearDeviceMetricsOverride', {});
    } catch (e) {
      console.error(e.message);
    }

    ws.close();
    process.exit(0);
  });

  ws.on('error', (e) => {
    console.error(e.message);
    process.exit(1);
  });
  setTimeout(() => {
    ws.close();
    process.exit(1);
  }, 20000);
}

main().catch((e) => {
  console.error(e.message);
  process.exit(1);
});
