# SCREENSHOT-INSTRUCTIONS.md — Chrome DevTools Interaction on macOS

Instructions for programmatically configuring, interacting with, and screenshotting Chrome Developer Tools on macOS. Written for AI coding agents (Claude Code, etc.).

---

## Screenshot Dimensions Standard

All screenshots in this project must be **1490x900 pixels at 1x DPR**. This is the de facto standard across existing documentation images and produces tighter, more focused captures of the XC console UI than 1920x1080.

| Property | Value |
| --- | --- |
| Target dimensions | 1490 x 900 px |
| Device pixel ratio | 1x |
| Format | PNG |
| Location | `docs/images/` |

**How this applies to each approach:**

- **Page screenshots** (chrome-devtools-mcp): Use `emulate` with viewport `"1490x900x1"` before capture — this forces exact pixel dimensions at 1x DPR. Verify with `sips -g pixelWidth -g pixelHeight`.
- **DevTools screenshots** (CDP `Page.captureScreenshot`): Captures at native resolution (e.g., ~2824x1636 on Retina). Resize after capture with `sips -z 900 1490 <input> --out docs/images/<name>.png`. Verify with `sips -g pixelWidth -g pixelHeight`.
- **After all page captures**: Reset emulation with `emulate` viewport `"0x0x0"` to restore defaults.

---

## Architecture: Two Approaches

There are two fundamentally different approaches. Know which one you need:

### Approach A: Programmatic Data (chrome-devtools-mcp)

The `chrome-devtools-mcp` MCP server gives you **programmatic access to page data** via Chrome DevTools Protocol. It can:

- List/filter network requests by resource type (`list_network_requests`)
- Get request/response bodies (`get_network_request`)
- Take screenshots of the **web page** (`take_screenshot`)
- Take a11y tree snapshots of the **web page** (`take_snapshot`)
- Click, type, and interact with **page elements** (`click`, `fill`, `type_text`, `press_key`)
- Run JavaScript on the page (`evaluate`)
- Run Lighthouse audits

**It CANNOT**: Screenshot the DevTools UI itself, visually manipulate DevTools panels, add/remove DevTools columns through its tools, or interact with DevTools-specific UI elements.

Use this when you need the **data** (network requests, console logs, performance metrics) but not a visual screenshot of the DevTools interface.

**Page screenshot workflow (chrome-devtools-mcp):**

1. Set exact viewport: `emulate` with viewport `"1490x900x1"` (the `x1` suffix forces deviceScaleFactor=1 — `resize_page` alone does NOT work on Retina displays)
2. Navigate and interact with the page as needed
3. Call `take_screenshot` with a `filePath` to save directly to `docs/images/`
4. Use descriptive filenames matching the image alt text (e.g., `csd-lb-csd-settings.png`)
5. Verify: `sips -g pixelWidth -g pixelHeight docs/images/<name>.png` — must be exactly 1490x900
6. After all captures, reset: `emulate` with viewport `"0x0x0"` to restore defaults

### Approach B: System-Level UI Automation (osascript + screencapture)

For **visual screenshots of the DevTools UI** — showing filters, columns, panels, waterfall charts, etc. — you must use macOS system tools:

- `osascript` for keyboard/window management (requires Accessibility permissions)
- `/usr/sbin/screencapture` for window capture (requires Screen Recording permissions)
- Chrome profile `Preferences` file for pre-configuring DevTools settings

**Use this when you need an actual image of what the DevTools looks like.**

---

## Prerequisites

### Required: Node.js + ws module

```bash
brew install node       # if not installed
npm install -g ws       # WebSocket library for CDP
```

When running CDP scripts: `NODE_PATH=$(npm root -g) node script.mjs`

### Optional: Screen Recording permission (only for `screencapture` fallback)

The **recommended CDP approach (Section 4, Method 1) needs no macOS permissions**. Only set up Screen Recording if you need the `screencapture` fallback.

macOS requires Screen Recording permission for any process that captures screen content. The `node` binary (which runs Claude Code) is a command-line tool without an app bundle, so macOS won't list it in the privacy panel. You need to create a minimal `.app` wrapper.

#### Step 1: Create the Node.app wrapper

Run this once to create the wrapper:

```bash
APP_DIR="$HOME/Applications/Node.app"
mkdir -p "$APP_DIR/Contents/MacOS"
cat > "$APP_DIR/Contents/Info.plist" << 'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>org.nodejs.node</string>
    <key>CFBundleName</key>
    <string>Node</string>
    <key>CFBundleExecutable</key>
    <string>node</string>
    <key>CFBundleVersion</key>
    <string>1.0</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
</dict>
</plist>
PLIST
ln -sf "$(which node)" "$APP_DIR/Contents/MacOS/node"
echo "Created $APP_DIR"
```

#### Step 2: Grant Screen Recording permission

1. Open System Settings:
   ```bash
   open "x-apple.systempreferences:com.apple.preference.security?Privacy_ScreenCapture"
   ```
2. Click the **+** button
3. Press **Cmd+Shift+G** in the file dialog to open "Go to Folder"
4. Paste: `~/Applications/`
5. Select **Node.app** → click **Open**
6. Toggle it **ON**
7. **Restart your terminal / Claude Code** — permissions take effect on next process launch

#### Step 3: Verify it works

```bash
/usr/sbin/screencapture -x /tmp/test-screenshot.png && echo "SUCCESS" || echo "FAILED - check permissions"
```

If you see `"could not create image from display"`, the permission hasn't been granted or the process needs to be restarted.

### Optional: Accessibility permission (for osascript keystrokes)

Only needed if you want to use `osascript` to send keystrokes via System Events. **The CDP approach (Section 5) does not require this** and is recommended instead.

If you do need it, create a similar wrapper and add it to **System Settings → Privacy & Security → Accessibility**. Same steps as above but selecting the Accessibility panel:

```bash
open "x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility"
```

### Node.js `ws` module (for CDP interaction)

The CDP approach requires the `ws` WebSocket library:

```bash
npm install -g ws
```

When running CDP scripts, use: `NODE_PATH=$(npm root -g) node script.mjs`

### Chrome path

These instructions assume Chrome is installed at the default location:
```
/Applications/Google Chrome.app/Contents/MacOS/Google Chrome
```

### `screencapture` path

On macOS, `screencapture` lives at `/usr/sbin/screencapture` which is **not** in the default `$PATH`. Always use the full path:
```bash
/usr/sbin/screencapture -l "$WID" -o -x output.png
```

---

## 1. Configuring Network Panel Columns

### Method: Edit Chrome Profile Preferences (MOST RELIABLE)

DevTools stores column visibility in the Chrome profile. Edit this **before launching Chrome** (or restart Chrome after editing) for guaranteed results.

**Preferences file location:**

```
~/.cache/chrome-devtools-mcp/chrome-profile/Default/Preferences
```

For standard Chrome (non-MCP):
```
~/Library/Application Support/Google/Chrome/Default/Preferences
```

**Key:** `devtools.preferences.network-log-columns`

**All available columns:**

| Column Key | Description | Default |
| --- | --- | --- |
| `name` | Request name/filename | ✅ visible |
| `method` | HTTP method (GET, POST, etc.) | ✅ visible |
| `status` | HTTP status code | ✅ visible |
| `type` | Resource type | ✅ visible |
| `initiator` | What triggered the request | ✅ visible |
| `size` | Transfer size | ✅ visible |
| `time` | Duration | ✅ visible |
| `path` | URL path | hidden |
| `url` | Full URL | hidden |
| `protocol` | HTTP/1.1, h2, h3, etc. | hidden |
| `scheme` | http or https | hidden |
| `domain` | Request domain | hidden |
| `remote-address` | Server IP:port | hidden |
| `remote-address-space` | IP address space | hidden |
| `cookies` | Number of request cookies | hidden |
| `set-cookies` | Number of response Set-Cookie headers | hidden |
| `priority` | Request priority | hidden |
| `connection-id` | Connection identifier | hidden |
| `waterfall` | Visual timing waterfall | hidden |
| `initiator-address-space` | Initiator's address space | hidden |
| `is-ad-related` | Ad-related request flag | hidden |
| `render-blocking` | Whether request blocks rendering | hidden |

**Response header columns** (prefix: `response-header-`):

| Column Key | Header |
| --- | --- |
| `response-header-cache-control` | Cache-Control |
| `response-header-connection` | Connection |
| `response-header-content-encoding` | Content-Encoding |
| `response-header-content-length` | Content-Length |
| `response-header-etag` | ETag |
| `response-header-keep-alive` | Keep-Alive |
| `response-header-last-modified` | Last-Modified |
| `response-header-server` | Server |
| `response-header-vary` | Vary |
| `response-header-has-overrides` | Has Overrides flag |

**Request header columns** (prefix: `request-header-`):

| Column Key | Header |
| --- | --- |
| `request-header-accept` | Accept |
| `request-header-accept-encoding` | Accept-Encoding |
| `request-header-accept-language` | Accept-Language |
| `request-header-content-type` | Content-Type |
| `request-header-origin` | Origin |
| `request-header-referer` | Referer |
| `request-header-sec-fetch-dest` | Sec-Fetch-Dest |
| `request-header-sec-fetch-mode` | Sec-Fetch-Mode |
| `request-header-user-agent` | User-Agent |

### Python script to configure columns

```python
import json, os

PREFS_PATH = "~/.cache/chrome-devtools-mcp/chrome-profile/Default/Preferences"
# For standard Chrome:
# PREFS_PATH = "~/Library/Application Support/Google/Chrome/Default/Preferences"

prefs_path = os.path.expanduser(PREFS_PATH)

with open(prefs_path) as f:
    prefs = json.load(f)

# Get current columns config
devtools_prefs = prefs.setdefault("devtools", {}).setdefault("preferences", {})
cols = json.loads(devtools_prefs.get("network-log-columns", "{}"))

# Define which columns you want visible
DESIRED_VISIBLE = [
    "name", "method", "status", "type", "domain",
    "remote-address", "size", "time", "waterfall",
    "response-header-content-type",
]

# Update visibility
for col_key in cols:
    cols[col_key]["visible"] = col_key in DESIRED_VISIBLE

# Write back
devtools_prefs["network-log-columns"] = json.dumps(cols)
with open(prefs_path, "w") as f:
    json.dump(prefs, f)

print("Columns updated. Restart Chrome for changes to take effect.")
```

### Bash one-liner to enable specific columns

```bash
# Enable domain and remote-address columns (add to existing)
python3 -c "
import json, os
p = os.path.expanduser('~/.cache/chrome-devtools-mcp/chrome-profile/Default/Preferences')
d = json.load(open(p))
cols = json.loads(d['devtools']['preferences']['network-log-columns'])
for c in ['domain', 'remote-address', 'waterfall']:
    if c in cols:
        cols[c]['visible'] = True
d['devtools']['preferences']['network-log-columns'] = json.dumps(cols)
json.dump(d, open(p, 'w'))
print('Done')
"
```

### ⚠️ CRITICAL: Kill Chrome BEFORE editing preferences

Chrome writes preferences to disk on exit. If you edit the file while Chrome is running, your changes will be overwritten when Chrome shuts down. The correct order is:

```bash
# 1. Kill Chrome completely
pkill -9 -f "Google Chrome"
sleep 3

# 2. Verify it's dead
pgrep -f "Google Chrome" && echo "Still running!" || echo "Ready to edit"

# 3. NOW edit preferences (they won't be overwritten)
python3 -c "..."

# 4. Relaunch Chrome (it reads preferences on startup)
```

This was verified — editing while Chrome runs results in all changes being reverted.

---

## 2. Configuring Network Filters

### Method A: Edit preferences file (pre-launch)

Set the `network-text-filter` preference:

```bash
python3 -c "
import json, os
p = os.path.expanduser('~/.cache/chrome-devtools-mcp/chrome-profile/Default/Preferences')
d = json.load(open(p))
d['devtools']['preferences']['network-text-filter'] = '\"method:POST domain:api.example.com\"'
json.dump(d, open(p, 'w'))
print('Filter set. Restart Chrome.')
"
```

### Method B: Type in filter bar via osascript (live)

Requires Accessibility permissions and DevTools to be open and focused:

```bash
# Focus DevTools window, then type in filter bar
osascript -e '
tell application "Google Chrome" to activate
delay 0.5
tell application "System Events"
  -- Open Command Menu
  keystroke "p" using {command down, shift down}
  delay 0.5
  -- Navigate to Network panel
  keystroke "Show Network"
  delay 0.5
  key code 36  -- Enter
  delay 1
  -- Focus filter bar with Cmd+F
  keystroke "f" using {command down}
  delay 0.3
  -- Select all existing filter text and replace
  keystroke "a" using {command down}
  delay 0.1
  key code 51  -- Delete
  delay 0.1
  -- Type new filter
  keystroke "method:POST"
  delay 0.3
end tell'
```

### Network filter syntax reference

**Text filters** (type in the filter bar):

| Filter | Matches |
| --- | --- |
| `example.com` | URL contains "example.com" |
| `/api\/v[0-9]+/` | Regular expression match on URL |
| `method:GET` | HTTP method is GET |
| `method:POST` | HTTP method is POST |
| `status-code:200` | Status code is 200 |
| `status-code:404` | Status code is 404 |
| `domain:api.example.com` | Request domain |
| `has-response-header:set-cookie` | Response has Set-Cookie |
| `has-response-header:x-custom` | Response has specific header |
| `larger-than:100k` | Response larger than 100KB |
| `larger-than:1M` | Response larger than 1MB |
| `mime-type:application/json` | MIME type match |
| `mime-type:text/html` | MIME type match |
| `scheme:https` | HTTPS only |
| `-scheme:data` | Exclude data URIs |
| `is:from-cache` | Served from cache |
| `is:running` | In-progress requests |
| `is:service-worker-initiated` | Service worker requests |
| `is:service-worker-intercepted` | SW intercepted |
| `cookie-domain:example.com` | Cookie domain match |
| `cookie-name:session` | Cookie name match |
| `cookie-path:/api` | Cookie path match |
| `priority:high` | Request priority |
| `mixed-content:all` | Mixed content requests |
| `resource-type:fetch` | Resource type filter |

**Combining filters** — separate with space (AND logic):

```
method:POST domain:api.example.com status-code:200
```

**Negation** — prefix with `-`:

```
-domain:cdn.example.com -mime-type:image/png
```

### Method C: Use chrome-devtools-mcp programmatically

For data extraction (not visual), the MCP's `list_network_requests` tool filters by resource type:

```
list_network_requests with resourceTypes: ["fetch", "xhr"]
```

Available resource types: `document`, `stylesheet`, `image`, `media`, `font`, `script`, `texttrack`, `xhr`, `fetch`, `prefetch`, `eventsource`, `websocket`, `manifest`, `signedexchange`, `ping`, `cspviolationreport`, `preflight`, `fedcm`, `other`

---

## 3. Configuring Other DevTools Settings via Preferences

### Set the active panel

```bash
python3 -c "
import json, os
p = os.path.expanduser('~/.cache/chrome-devtools-mcp/chrome-profile/Default/Preferences')
d = json.load(open(p))
d['devtools']['preferences']['panel-selected-tab'] = '\"network\"'  # or: elements, console, sources, etc.
json.dump(d, open(p, 'w'))
"
```

### Set dock state

```bash
# Options: "right", "bottom", "undocked"
python3 -c "
import json, os
p = os.path.expanduser('~/.cache/chrome-devtools-mcp/chrome-profile/Default/Preferences')
d = json.load(open(p))
d['devtools']['preferences']['currentDockState'] = '\"undocked\"'
json.dump(d, open(p, 'w'))
"
```

---

## 4. Taking Screenshots of DevTools

### Method 1: CDP Page.captureScreenshot (RECOMMENDED ✅)

**No macOS permissions needed.** This captures the DevTools UI directly via the Chrome DevTools Protocol by screenshotting the DevTools page target (which is itself a web page at `devtools://devtools/bundled/devtools_app.html`).

**Requirements:** Chrome must be launched with `--remote-debugging-port=9222`

```bash
# 1. Find the DevTools page target WebSocket URL
DEVTOOLS_WS=$(curl -s http://localhost:9222/json | python3 -c "
import json, sys
for t in json.load(sys.stdin):
    if 'devtools_app.html' in t.get('url', ''):
        print(t['webSocketDebuggerUrl'])
        break
")

# 2. Capture screenshot via CDP
cat > /tmp/cdp-screenshot.mjs << 'JSEOF'
import { WebSocket } from 'ws';
import { writeFileSync } from 'fs';

const wsUrl = process.argv[2];
const outputPath = process.argv[3] || 'devtools-screenshot.png';

const ws = new WebSocket(wsUrl);
ws.on('open', () => {
    ws.send(JSON.stringify({
        id: 1,
        method: 'Page.captureScreenshot',
        params: { format: 'png' }
    }));
});

ws.on('message', (data) => {
    const msg = JSON.parse(data.toString());
    if (msg.id === 1 && msg.result && msg.result.data) {
        writeFileSync(outputPath, Buffer.from(msg.result.data, 'base64'));
        console.log(`Screenshot saved: ${outputPath}`);
        ws.close();
        process.exit(0);
    } else if (msg.id === 1) {
        console.error('Error:', JSON.stringify(msg));
        ws.close();
        process.exit(1);
    }
});

setTimeout(() => { ws.close(); process.exit(1); }, 10000);
JSEOF

NODE_PATH=$(npm root -g) node /tmp/cdp-screenshot.mjs "$DEVTOOLS_WS" "devtools-screenshot.png"
```

**After capture, resize to the standard 1490x900:**

```bash
sips -z 900 1490 devtools-screenshot.png --out docs/images/devtools-screenshot.png
# Verify dimensions
sips -g pixelWidth -g pixelHeight docs/images/devtools-screenshot.png
```

**Why this is better than screencapture:**
- No Screen Recording permission needed
- No `.app` wrapper needed
- Works reliably across process restarts (no TCC flakiness)
- Works headless (no window needs to be visible)
- Captures at the DevTools' native resolution (resize to 1490x900 after capture)

### Method 2: screencapture (Fallback)

Use this if you can't use CDP (e.g., no `--remote-debugging-port`). **Requires Screen Recording permission** (see Prerequisites).

#### Find the DevTools window CGWindowID

AppleScript window IDs ≠ CGWindowIDs. Use Swift to get the correct ID:

```bash
DEVTOOLS_WID=$(swift -e '
import CoreGraphics
if let list = CGWindowListCopyWindowInfo(.optionOnScreenOnly, kCGNullWindowID) as? [[String: Any]] {
    for w in list {
        let owner = w["kCGWindowOwnerName"] as? String ?? ""
        let name = w["kCGWindowName"] as? String ?? ""
        let id = w["kCGWindowNumber"] as? Int ?? 0
        let layer = w["kCGWindowLayer"] as? Int ?? -1
        let bounds = w["kCGWindowBounds"] as? [String: Any] ?? [:]
        let width = bounds["Width"] as? Int ?? 0
        let height = bounds["Height"] as? Int ?? 0
        if owner.contains("Chrome") && layer == 0 && width > 100 && height > 100 {
            if name.contains("DevTools") || name.contains("Developer Tools") {
                print(id)
            }
        }
    }
}
' 2>/dev/null | head -1)
```

#### Capture

```bash
/usr/sbin/screencapture -l "$DEVTOOLS_WID" -o -x screenshot.png

# With delay (let UI settle):
/usr/sbin/screencapture -l "$DEVTOOLS_WID" -o -x -T 2 screenshot.png
```

**Flags:**

| Flag | Purpose |
| --- | --- |
| `-l <id>` | Capture specific window by CGWindowID |
| `-o` | Exclude window shadow |
| `-x` | No screenshot sound |
| `-T <sec>` | Delay before capture |

**Note:** `screencapture` lives at `/usr/sbin/screencapture` which may not be in `$PATH`. Always use the full path.

#### Screen Recording permission is unreliable

macOS dynamically re-evaluates Screen Recording permissions. It may work initially but stop working after process restarts or Chrome relaunches. If `screencapture -l` fails with `"could not create image from window"`:

1. Reset permissions: `tccutil reset ScreenCapture`
2. Re-grant via System Settings (see Prerequisites)
3. Restart your terminal / Claude Code process

**This is why the CDP approach (Method 1) is strongly recommended.**

---

## 5. DevTools Interaction via CDP (NO Accessibility Permissions Needed)

When Chrome is launched with `--remote-debugging-port=9222`, you can send keystrokes and interact with the DevTools UI directly via the Chrome DevTools Protocol. This **bypasses all macOS permission issues**.

### Connect to the DevTools page target

```bash
# Find the DevTools page WebSocket URL
DEVTOOLS_WS=$(curl -s http://localhost:9222/json | python3 -c "
import json, sys
for t in json.load(sys.stdin):
    if 'devtools_app.html' in t.get('url', ''):
        print(t['webSocketDebuggerUrl'])
        break
")
```

### Open the Command Menu (Cmd+Shift+P) via CDP

Use `Runtime.evaluate` to dispatch a keyboard event directly into the DevTools DOM:

```javascript
// Send via WebSocket to the DevTools target
{
    "method": "Runtime.evaluate",
    "params": {
        "expression": "document.dispatchEvent(new KeyboardEvent('keydown', { key: 'P', code: 'KeyP', metaKey: true, shiftKey: true, bubbles: true, cancelable: true }));",
        "returnByValue": true
    }
}
```

### Type text into Command Menu or filter bar

Use `Input.insertText` to type text:

```javascript
{
    "method": "Input.insertText",
    "params": { "text": "Show Network" }
}
```

### Press Enter / special keys

Use `Input.dispatchKeyEvent`:

```javascript
{
    "method": "Input.dispatchKeyEvent",
    "params": {
        "type": "keyDown",
        "key": "Enter",
        "code": "Enter",
        "windowsVirtualKeyCode": 13
    }
}
```

### Complete Node.js helper script (VERIFIED ✅)

Save this and run with `NODE_PATH=$(npm root -g) node devtools-interact.mjs`:

```javascript
import { WebSocket } from 'ws';

const DEVTOOLS_WS = process.argv[2]; // Pass WebSocket URL as argument

async function sendCDP(ws, method, params) {
    const id = Math.floor(Math.random() * 100000);
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

async function openCommandMenu(ws) {
    await sendCDP(ws, 'Runtime.evaluate', {
        expression: `document.dispatchEvent(new KeyboardEvent('keydown', {
            key: 'P', code: 'KeyP', metaKey: true, shiftKey: true,
            bubbles: true, cancelable: true
        }));`,
        returnByValue: true
    });
}

async function typeText(ws, text) {
    await sendCDP(ws, 'Input.insertText', { text });
}

async function sendEnterKey(ws) {
    await sendCDP(ws, 'Input.dispatchKeyEvent', {
        type: 'keyDown', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13
    });
    await sendCDP(ws, 'Input.dispatchKeyEvent', {
        type: 'keyUp', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13
    });
}

async function pressEscape(ws) {
    await sendCDP(ws, 'Input.dispatchKeyEvent', {
        type: 'keyDown', key: 'Escape', code: 'Escape', windowsVirtualKeyCode: 27
    });
    await sendCDP(ws, 'Input.dispatchKeyEvent', {
        type: 'keyUp', key: 'Escape', code: 'Escape', windowsVirtualKeyCode: 27
    });
}

async function runCommand(ws, command) {
    await openCommandMenu(ws);
    await new Promise(r => setTimeout(r, 300));
    await typeText(ws, command);
    await new Promise(r => setTimeout(r, 300));
    await sendEnterKey(ws);
    await new Promise(r => setTimeout(r, 500));
}

// Usage: switch panels, toggle features, etc.
const ws = new WebSocket(DEVTOOLS_WS);
ws.on('open', async () => {
    // Example: switch to Network panel
    await runCommand(ws, 'Show Network');
    console.log('Switched to Network panel');
    ws.close();
    process.exit(0);
});

ws.on('error', (e) => { console.error(e.message); process.exit(1); });
setTimeout(() => { ws.close(); process.exit(0); }, 10000);
```

### Launch Chrome with remote debugging

Always include `--remote-debugging-port=9222` when launching Chrome for CDP interaction:

```bash
/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome \
  --user-data-dir="$HOME/.cache/chrome-devtools-mcp/chrome-profile" \
  --auto-open-devtools-for-tabs \
  --remote-debugging-port=9222 \
  --no-first-run \
  "$TARGET_URL" &
```

---

## 6. DevTools Panel Navigation via osascript (Alternative)

**Note:** This approach requires Accessibility permissions. Prefer the CDP approach (Section 5) when possible.

All of these require Accessibility permissions for osascript and the DevTools window to be focused.

### Focus Chrome and DevTools

```bash
osascript -e '
tell application "Google Chrome"
  activate
  -- If DevTools is undocked, bring it to front
  repeat with w in every window
    if name of w starts with "DevTools" or name of w starts with "Developer Tools" then
      set index of w to 1
      exit repeat
    end if
  end repeat
end tell'
```

### Open/close DevTools

```bash
# Toggle DevTools: Cmd+Option+I
osascript -e '
tell application "Google Chrome" to activate
delay 0.3
tell application "System Events"
  keystroke "i" using {command down, option down}
end tell'
```

### Undock/dock DevTools

```bash
# Toggle dock mode: Cmd+Shift+D
osascript -e '
tell application "System Events"
  keystroke "d" using {command down, shift down}
end tell'
```

### Switch panels via Command Menu (MOST RELIABLE)

The DevTools Command Menu (`Cmd+Shift+P`) is text-based and deterministic — always prefer it over clicking:

```bash
osascript -e '
tell application "System Events"
  -- Open Command Menu
  keystroke "p" using {command down, shift down}
  delay 0.5
  -- Type the command
  keystroke "Show Network"
  delay 0.5
  -- Execute
  key code 36  -- Enter
end tell'
```

**Command Menu panel commands:**

| Command | Panel |
| --- | --- |
| `Show Network` | Network |
| `Show Console` | Console |
| `Show Elements` | Elements |
| `Show Sources` | Sources |
| `Show Performance` | Performance |
| `Show Application` | Application |
| `Show Memory` | Memory |
| `Show Security` | Security |
| `Show Lighthouse` | Lighthouse |
| `Show Coverage` | Coverage |
| `Show Layers` | Layers |

### Direct keyboard shortcuts

| Panel | Shortcut | osascript |
| --- | --- | --- |
| Elements | `Cmd+Shift+C` | `keystroke "c" using {command down, shift down}` |
| Console | `Cmd+Shift+J` | `keystroke "j" using {command down, shift down}` |
| Next panel | `Cmd+]` | `keystroke "]" using {command down}` |
| Prev panel | `Cmd+[` | `keystroke "[" using {command down}` |

---

## 7. Key Codes Reference

For `key code` in AppleScript:

| Key | Code | Key | Code |
| --- | --- | --- | --- |
| Return/Enter | 36 | Delete/Backspace | 51 |
| Tab | 48 | Escape | 53 |
| Space | 49 | Left Arrow | 123 |
| Right Arrow | 124 | Up Arrow | 126 |
| Down Arrow | 125 | F1 | 122 |
| F5 | 96 | F12 | 111 |

---

## 8. Complete Workflow Examples

### Example A: Pre-configure + CDP screenshot (RECOMMENDED, VERIFIED ✅)

Zero macOS permissions needed. Kill Chrome, configure preferences, relaunch with CDP, screenshot via CDP.

```bash
#!/bin/bash
set -e

TARGET_URL="${1:-https://example.com}"
OUTPUT="${2:-devtools-screenshot.png}"
PREFS="$HOME/.cache/chrome-devtools-mcp/chrome-profile/Default/Preferences"

# 1. Kill Chrome completely (MUST be dead before editing preferences)
pkill -9 -f "Google Chrome" 2>/dev/null || true
sleep 3
pgrep -f "Google Chrome" && { echo "ERROR: Chrome still running"; exit 1; }

# 2. Configure preferences
python3 << 'PYEOF'
import json, os

prefs_path = os.path.expanduser("~/.cache/chrome-devtools-mcp/chrome-profile/Default/Preferences")
with open(prefs_path) as f:
    prefs = json.load(f)

dp = prefs.setdefault("devtools", {}).setdefault("preferences", {})

# Set desired columns
cols = json.loads(dp.get("network-log-columns", "{}"))
desired = ["name", "method", "status", "domain", "type", "remote-address", "size", "time", "waterfall"]
for col in cols:
    cols[col]["visible"] = col in desired
dp["network-log-columns"] = json.dumps(cols)

# Set Network as active panel
dp["panel-selected-tab"] = '"network"'

# Undock DevTools into its own window
dp["currentDockState"] = '"undocked"'

with open(prefs_path, "w") as f:
    json.dump(prefs, f)

print("Preferences configured.")
PYEOF

# 3. Relaunch Chrome with auto-open-devtools and remote debugging
/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome \
  --user-data-dir="$HOME/.cache/chrome-devtools-mcp/chrome-profile" \
  --auto-open-devtools-for-tabs \
  --remote-debugging-port=9222 \
  --no-first-run \
  "$TARGET_URL" &>/dev/null &
disown
sleep 6

# 4. Wait for CDP to be ready
for i in $(seq 1 10); do
    curl -s http://localhost:9222/json/version > /dev/null 2>&1 && break
    sleep 1
done

# 5. Screenshot DevTools via CDP (no permissions needed)
DEVTOOLS_WS=$(curl -s http://localhost:9222/json | python3 -c "
import json, sys
for t in json.load(sys.stdin):
    if 'devtools_app.html' in t.get('url', ''):
        print(t['webSocketDebuggerUrl'])
        break
")

if [ -z "$DEVTOOLS_WS" ]; then
    echo "ERROR: DevTools target not found in CDP"
    exit 1
fi

cat > /tmp/cdp-screenshot.mjs << 'JSEOF'
import { WebSocket } from 'ws';
import { writeFileSync } from 'fs';

const wsUrl = process.argv[2];
const outputPath = process.argv[3];

const ws = new WebSocket(wsUrl);
ws.on('open', () => {
    ws.send(JSON.stringify({
        id: 1,
        method: 'Page.captureScreenshot',
        params: { format: 'png' }
    }));
});

ws.on('message', (data) => {
    const msg = JSON.parse(data.toString());
    if (msg.id === 1 && msg.result && msg.result.data) {
        writeFileSync(outputPath, Buffer.from(msg.result.data, 'base64'));
        console.log(`Screenshot saved: ${outputPath}`);
        ws.close();
        process.exit(0);
    } else if (msg.id === 1) {
        console.error('Error:', JSON.stringify(msg));
        ws.close();
        process.exit(1);
    }
});

setTimeout(() => { console.error('Timeout'); ws.close(); process.exit(1); }, 10000);
JSEOF

NODE_PATH=$(npm root -g) node /tmp/cdp-screenshot.mjs "$DEVTOOLS_WS" "$OUTPUT"

# 6. Resize to standard 1490x900
sips -z 900 1490 "$OUTPUT" --out "$OUTPUT"
echo "Final dimensions:"
sips -g pixelWidth -g pixelHeight "$OUTPUT"
```

### Example B: Live CDP interaction — switch panel, set filter, screenshot (VERIFIED ✅)

Use when Chrome is already running with `--remote-debugging-port=9222` and you need to change panels/filters dynamically. **No macOS permissions needed.**

```bash
#!/bin/bash
set -e

COMMAND="${1:-Show Network}"   # DevTools Command Menu command
OUTPUT="${2:-devtools-live.png}"

# 1. Find the DevTools page target
DEVTOOLS_WS=$(curl -s http://localhost:9222/json | python3 -c "
import json, sys
for t in json.load(sys.stdin):
    if 'devtools_app.html' in t.get('url', ''):
        print(t['webSocketDebuggerUrl'])
        break
")

if [ -z "$DEVTOOLS_WS" ]; then
    echo "ERROR: No DevTools target found. Is Chrome running with --remote-debugging-port=9222?"
    exit 1
fi

# 2. Send command via CDP, then screenshot
cat > /tmp/cdp-interact.mjs << 'JSEOF'
import { WebSocket } from 'ws';
import { writeFileSync } from 'fs';

const wsUrl = process.argv[2];
const command = process.argv[3];
const outputPath = process.argv[4];

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

const ws = new WebSocket(wsUrl);
ws.on('open', async () => {
    // Open Command Menu (Cmd+Shift+P)
    await sendCDP(ws, 'Runtime.evaluate', {
        expression: `document.dispatchEvent(new KeyboardEvent('keydown', {
            key: 'P', code: 'KeyP', metaKey: true, shiftKey: true,
            bubbles: true, cancelable: true
        }));`,
        returnByValue: true
    });
    await new Promise(r => setTimeout(r, 500));

    // Type the command
    await sendCDP(ws, 'Input.insertText', { text: command });
    await new Promise(r => setTimeout(r, 500));

    // Press Enter
    await sendCDP(ws, 'Input.dispatchKeyEvent', {
        type: 'keyDown', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13
    });
    await sendCDP(ws, 'Input.dispatchKeyEvent', {
        type: 'keyUp', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13
    });
    await new Promise(r => setTimeout(r, 1000));

    // Take screenshot
    const result = await sendCDP(ws, 'Page.captureScreenshot', { format: 'png' });
    if (result && result.data) {
        writeFileSync(outputPath, Buffer.from(result.data, 'base64'));
        console.log(`Screenshot saved: ${outputPath}`);
    }

    ws.close();
    process.exit(0);
});

ws.on('error', (e) => { console.error(e.message); process.exit(1); });
setTimeout(() => { ws.close(); process.exit(1); }, 15000);
JSEOF

NODE_PATH=$(npm root -g) node /tmp/cdp-interact.mjs "$DEVTOOLS_WS" "$COMMAND" "$OUTPUT"
```

**Usage examples:**

```bash
# Switch to Console panel and screenshot
./example-b.sh "Show Console" console.png

# Switch to Network panel and screenshot
./example-b.sh "Show Network" network.png

# Switch to Performance panel and screenshot
./example-b.sh "Show Performance" performance.png
```

### Example C: Resize DevTools window before screenshot

```bash
# Set DevTools window to specific dimensions (uses AppleScript, no special permissions)
osascript -e '
tell application "Google Chrome"
  repeat with w in every window
    if name of w starts with "DevTools" or name of w starts with "Developer Tools" then
      set bounds of w to {100, 100, 1500, 900}  -- {left, top, right, bottom}
      exit repeat
    end if
  end repeat
end tell'
sleep 0.5

# Then screenshot via CDP (no need to resize for CDP screenshots — they capture at native resolution)
```

---

## 9. Troubleshooting

### "could not create image from window" / "could not create image from display"

**Cause:** Screen Recording permission not granted for the process running `screencapture`.

**Fix:**
1. Create the Node.app wrapper (see Prerequisites, Step 1)
2. Add it to Screen Recording (see Prerequisites, Step 2)
3. **Restart your terminal / Claude Code process** — permissions only take effect on new processes

If the permission prompt appeared but Node.app doesn't show in the list, this is a known macOS issue with CLI binaries. The `.app` wrapper in the Prerequisites section solves this.

### "osascript is not allowed to send keystrokes" (error 1002)

**Cause:** Accessibility permission not granted. **Recommendation:** Use the CDP approach (Section 5) instead — it doesn't need Accessibility permissions at all.

If you still need osascript keystrokes:
1. Open Accessibility settings: `open "x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility"`
2. Add your terminal app (Terminal.app, iTerm2, etc.)
3. If running via `node`, add `Node.app` (same wrapper from Prerequisites)
4. Restart the process

### screencapture command not found

Use the full path: `/usr/sbin/screencapture` — it's not in the default `$PATH`.

### DevTools window not found by swift script

- DevTools may be **docked** (not a separate window). Set `currentDockState` to `"undocked"` in preferences and restart Chrome.
- If you launched Chrome with `--auto-open-devtools-for-tabs`, DevTools should be undocked if the preference is set.
- The window might have an empty name. Identify windows by size instead — DevTools is typically narrower than the main page window.

### Column/filter changes not reflected

- **Chrome overwrites preferences on exit.** You MUST: kill Chrome → edit preferences → relaunch. If you edit while Chrome is running, changes will be lost.
- When editing preferences JSON, note that string values in `devtools.preferences` are **double-encoded** — the outer JSON has the value as a string, which itself contains JSON. Example: `"network-text-filter": "\"method:POST\""` (the inner quotes are part of the value).

### CDP connection refused (port 9222)

- Chrome must be launched with `--remote-debugging-port=9222`
- Only one Chrome instance can bind to a given port. If another instance is running with the same port, kill it first.
- Verify with: `curl -s http://localhost:9222/json/version`

### CDP keystrokes not reaching DevTools

- Use `Runtime.evaluate` with `document.dispatchEvent(new KeyboardEvent(...))` on the **DevTools page target** (URL contains `devtools_app.html`), not the regular page target
- `Input.dispatchKeyEvent` alone may not trigger DevTools shortcuts — the DOM dispatch approach works reliably

### Wrong window captured

List all Chrome windows to verify:

```bash
swift -e '
import CoreGraphics
if let list = CGWindowListCopyWindowInfo(.optionOnScreenOnly, kCGNullWindowID) as? [[String: Any]] {
    for w in list {
        let owner = w["kCGWindowOwnerName"] as? String ?? ""
        if owner.contains("Chrome") {
            let name = w["kCGWindowName"] as? String ?? "(none)"
            let id = w["kCGWindowNumber"] as? Int ?? 0
            let bounds = w["kCGWindowBounds"] as? [String: Any] ?? [:]
            print("ID=\(id) Name=\(name) Bounds=\(bounds)")
        }
    }
}
'
```

---

## 10. First-Time Setup Checklist

For new users setting up on a fresh Mac:

```bash
# 1. Install dependencies
brew install node  # if not already installed
npm install -g ws  # WebSocket library for CDP interaction

# 2. Create Node.app wrapper for Screen Recording permission
APP_DIR="$HOME/Applications/Node.app"
mkdir -p "$APP_DIR/Contents/MacOS"
cat > "$APP_DIR/Contents/Info.plist" << 'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleIdentifier</key>
    <string>org.nodejs.node</string>
    <key>CFBundleName</key>
    <string>Node</string>
    <key>CFBundleExecutable</key>
    <string>node</string>
    <key>CFBundleVersion</key>
    <string>1.0</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
</dict>
</plist>
PLIST
ln -sf "$(which node)" "$APP_DIR/Contents/MacOS/node"
echo "✅ Created Node.app wrapper"

# 3. Grant Screen Recording permission
open "x-apple.systempreferences:com.apple.preference.security?Privacy_ScreenCapture"
echo "➡️  Click + → Cmd+Shift+G → ~/Applications/ → select Node.app → toggle ON"
echo "➡️  Then restart your terminal"

# 4. Verify Chrome is installed
ls "/Applications/Google Chrome.app" > /dev/null 2>&1 && echo "✅ Chrome found" || echo "❌ Install Google Chrome"

# 5. Verify screencapture works (run AFTER restarting terminal)
/usr/sbin/screencapture -x /tmp/test.png && echo "✅ Screen capture works" || echo "❌ Check Screen Recording permission"
```

---

## 11. Screenshot Annotations (Badges/Labels)

Screenshots can be annotated with colored badge labels to highlight specific elements — for example, tagging scripts as "CSD Telemetry (sync)" or "Third-party" in a DevTools Elements panel screenshot.

This uses an HTML/CSS overlay approach: the screenshot becomes the background of an HTML page, badges are positioned with absolute CSS, and the result is captured via CDP at exact pixel dimensions. **No image editing tools needed.**

### Annotation tool: `scripts/annotate-screenshot.mjs`

Saved in the project at `scripts/annotate-screenshot.mjs` with its HTML template at `scripts/annotate-template.html`.

**Usage:**

```bash
NODE_PATH=$(npm root -g) node scripts/annotate-screenshot.mjs \
  <input-screenshot> \
  <output-path> \
  <width> <height> \
  '<badges-json>'
```

**Requirements:** Chrome running with `--remote-debugging-port=9222`, `npm install -g ws`

### Badge classes

| Class | Style | Use for |
| --- | --- | --- |
| `badge-csd` | Amber/gold background, dark text | CSD telemetry scripts, product-specific highlights |
| `badge-thirdparty` | Medium grey background, white text | Third-party scripts, external resources |
| `badge-info` | Blue background, white text | Informational callouts |
| `badge-warning` | Red background, white text | Warnings, errors, vulnerabilities |
| `badge-success` | Green background, white text | Verified, passing, correct items |

### Badge JSON format

```json
[
  {
    "text": "CSD Telemetry (sync)",
    "class": "badge-csd",
    "centerY": 135,
    "left": 420
  },
  {
    "text": "Third-party",
    "class": "badge-thirdparty",
    "centerY": 300,
    "left": 850
  }
]
```

Each badge has:
- `text` — label text
- `class` — one of the badge classes above (or use `style` for custom CSS)
- `centerY` — **(preferred)** Y coordinate of the vertical center of the target row. Badge auto-centers via `translateY(-50%)`.
- `top` — (legacy) top edge of badge in pixels. Still supported for backwards compatibility.
- `left` — pixels from the left of the image
- `style` (optional) — additional inline CSS, e.g. `"background: #8E24AA; color: #fff;"`

Use `centerY` for new annotations. Open the raw screenshot in Preview, hover over the vertical center of the target row — the Y coordinate shown in the info panel is your `centerY` value. No offset math needed.

### Complete example: annotate a DevTools Elements panel screenshot

```bash
# 1. Take a screenshot (via CDP or screencapture)
# ... screenshot saved as docs/images/raw-devtools-elements.png

# 2. Annotate it with badges (using centerY for vertical centering)
NODE_PATH=$(npm root -g) node scripts/annotate-screenshot.mjs \
  docs/images/raw-devtools-elements.png \
  docs/images/csd-injected-scripts.png \
  1490 900 \
  '[
    {"text":"CSD Telemetry (sync)","class":"badge-csd","centerY":135,"left":420},
    {"text":"Third-party","class":"badge-thirdparty","centerY":300,"left":850},
    {"text":"Third-party","class":"badge-thirdparty","centerY":323,"left":740},
    {"text":"CSD Telemetry (async)","class":"badge-csd","centerY":347,"left":740}
  ]'
```

### Tips for positioning badges

1. **Take the screenshot first**, then open it in Preview or a browser to find the pixel coordinates for badge placement.
2. **Use `centerY` for vertical positioning.** Open the raw screenshot in Preview. Hover over the vertical center of the target row — the Y coordinate is your `centerY` value. No offset math needed.
3. **Coordinates are relative to the output dimensions** (e.g., 1490x900), not the source image's native resolution. The annotation tool scales the source image to fit.
4. **Place badges inline with the code/content they annotate** — typically to the right of the element, vertically centered on the line.
5. **Use `sips -g pixelWidth -g pixelHeight`** to verify the final annotated image is the correct dimensions.

### Customizing badge styles

Edit `scripts/annotate-template.html` to add new badge classes or adjust existing styles. The CSS uses standard properties:

```css
.badge-custom {
    background: #8E24AA;
    color: #fff;
    border: 1px solid #6A1B9A;
}
```

Or use inline styles in the badge JSON:

```json
{"text": "Custom Label", "class": "badge", "centerY": 110, "left": 500, "style": "background: #8E24AA; color: #fff; border: 1px solid #6A1B9A;"}
```

---

## 12. Tips for AI Agents

1. **All screenshots must be 1490x900 at 1x DPR.** For page screenshots, use `emulate` with viewport `"1490x900x1"`. For DevTools screenshots, capture via CDP and resize with `sips -z 900 1490`. Always verify with `sips -g pixelWidth -g pixelHeight`.

2. **Use CDP for everything.** The CDP approach (Sections 4-5) requires zero macOS permissions. Use `Page.captureScreenshot` for screenshots and `Runtime.evaluate` + `document.dispatchEvent(KeyboardEvent)` for interaction. Never rely on `screencapture` or `osascript` keystrokes as the primary approach.

3. **The recommended workflow:**
   - Kill Chrome → edit preferences (columns, filters, dock state, panel) → relaunch with `--remote-debugging-port=9222 --auto-open-devtools-for-tabs`
   - For runtime interaction: CDP to open Command Menu, type commands, press Enter
   - Screenshot via CDP `Page.captureScreenshot` on the DevTools page target
   - Resize to 1490x900 with `sips -z 900 1490`
   - **No macOS permissions needed for any of this**

4. **Kill Chrome before editing preferences.** Chrome overwrites preferences on exit. The correct order is: kill → edit → relaunch. Never edit while Chrome is running.

5. **Double-encoding in preferences:** Values in `devtools.preferences` are JSON strings containing JSON. When setting `network-text-filter`, the Python code is:
   ```python
   dp["network-text-filter"] = '"method:POST"'  # Note: outer quotes are Python, inner quotes are the JSON string value
   ```

6. **When using CDP, target the DevTools page.** The DevTools UI is itself a web page. Find it by looking for the target with URL containing `devtools_app.html` in the CDP target list (`curl -s http://localhost:9222/json`).

7. **For data-only needs, skip the screenshot entirely.** Use `chrome-devtools-mcp`'s `list_network_requests` with `resourceTypes` filter to get structured data. This is faster and doesn't require launching a separate Chrome instance.

8. **Chrome can only bind to one debugging port.** If `chrome-devtools-mcp` is running its own Chrome instance, you can't launch a second one on the same profile. Either stop the MCP server first, or use a different `--user-data-dir`.

9. **Undock DevTools for cleaner screenshots.** Set `currentDockState` to `"undocked"` in preferences. This makes the DevTools page target render at full size.

10. **Wait for CDP readiness after launch.** Chrome takes a few seconds to start. Poll `curl -s http://localhost:9222/json/version` in a loop before attempting CDP connections.

11. **`npm install -g ws` is required.** Run CDP scripts with `NODE_PATH=$(npm root -g) node script.mjs` to find the global module.
