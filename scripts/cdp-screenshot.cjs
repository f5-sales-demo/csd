// CDP screenshot script — connects to a DevTools target, sets viewport, captures PNG.
// Usage: NODE_PATH=$(npm root -g) node scripts/cdp-screenshot.cjs <ws-url> <output-path>
//
// Extracted from SCREENSHOT-INSTRUCTIONS.md Example A.
// Sets Emulation.setDeviceMetricsOverride to 1280x720 at 1x DPR before capture.

const { WebSocket } = require('ws');
const { writeFileSync } = require('fs');

const wsUrl = process.argv[2];
const outputPath = process.argv[3] || 'devtools-screenshot.png';

if (!wsUrl) {
  console.error('Usage: node cdp-screenshot.cjs <ws-url> [output-path]');
  process.exit(1);
}

const ws = new WebSocket(wsUrl);
ws.on('open', () => {
    // Force DevTools viewport to exact 1280x720 at 1x DPR
    ws.send(JSON.stringify({
        id: 1,
        method: 'Emulation.setDeviceMetricsOverride',
        params: { width: 1280, height: 720, deviceScaleFactor: 1, mobile: false }
    }));
});

ws.on('message', (data) => {
    const msg = JSON.parse(data.toString());
    if (msg.id === 1) {
        if (msg.error) {
            console.error('Emulation override failed:', JSON.stringify(msg.error));
            ws.close();
            process.exit(1);
        }
        // Override applied — capture
        ws.send(JSON.stringify({
            id: 2,
            method: 'Page.captureScreenshot',
            params: { format: 'png' }
        }));
    } else if (msg.id === 2 && msg.result && msg.result.data) {
        writeFileSync(outputPath, Buffer.from(msg.result.data, 'base64'));
        console.log(`Screenshot saved: ${outputPath}`);
        ws.close();
        process.exit(0);
    } else if (msg.id === 2) {
        console.error('Screenshot error:', JSON.stringify(msg));
        ws.close();
        process.exit(1);
    }
});

ws.on('error', (e) => { console.error(e.message); process.exit(1); });
setTimeout(() => { console.error('Timeout'); ws.close(); process.exit(1); }, 10000);
