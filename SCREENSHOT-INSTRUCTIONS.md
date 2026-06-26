# SCREENSHOT-INSTRUCTIONS.md — Chrome DevTools Interaction on macOS

Instructions for programmatically configuring, interacting with, and screenshotting Chrome Developer Tools on macOS. Written for AI coding agents (Claude Code, etc.).

---

## Screenshot Dimensions Standard

This project uses a **dual-resolution standard** — both 16:9 aspect ratio, at 1x DPR:

| Screenshot type | Dimensions | Rationale |
| --- | --- | --- |
| **Page screenshots** (XC console, web app) | **1600 x 900** (HD+) | Full-width UI captures render well in the docs content column |
| **DevTools screenshots** (Network, Console, Elements) | **1280 x 720** (HD) | Smaller viewport makes DevTools text ~20% larger relative to the image, improving readability when scaled down on the docs site |

| Property | Page | DevTools |
| --- | --- | --- |
| Target dimensions | 1600 x 900 px | 1280 x 720 px |
| Aspect ratio | 16:9 | 16:9 |
| Device pixel ratio | 1x | 1x |
| Format | PNG | PNG |
| Location | `docs/images/` | `docs/images/` |
| Naming convention | `<name>-light.png` / `<name>-dark.png` | `<name>-light.png` / `<name>-dark.png` |

**How this applies to each approach:**

- **Page screenshots** (chrome-devtools-mcp): Use `emulate` with viewport `"1600x900x1"` before capture — this forces exact pixel dimensions at 1x DPR. Verify with `sips -g pixelWidth -g pixelHeight`.
- **DevTools screenshots** (CDP): Use `Emulation.setDeviceMetricsOverride` with `width: 1280, height: 720, deviceScaleFactor: 1` before `Page.captureScreenshot` — captures at exact 1280x720. No post-capture resize needed. Verify with `sips -g pixelWidth -g pixelHeight`.
- **After all page captures**: Reset emulation with `emulate` viewport `"0x0x0"` to restore defaults.

---

## Dark Mode Conventions

The `<Screenshot>` component supports `light` and `dark` attributes. Whether you provide both depends on the screenshot source:

| Source | Has dark mode? | `<Screenshot>` pattern | Example |
| --- | --- | --- | --- |
| **F5 XC Console** (`csd-*` screenshots) | No — XC Console is light-only | `light="..."` (no `dark=`) | `<Screenshot light="/images/csd-dashboard.png" alt="..." />` |
| **Juice Shop / overlay** (demo app screenshots) | Fixed dark theme — same image for both modes | `light="..." dark="..."` with **identical paths** | `<Screenshot light="/images/demo-app-home.png" dark="/images/demo-app-home.png" alt="..." />` |
| **Chrome DevTools** (console, network, elements) | Yes — proper light/dark pairs | `light="...-light.png" dark="...-dark.png"` | `<Screenshot light="/images/devtools-console-light.png" dark="/images/devtools-console-dark.png" alt="..." />` |

**Why Juice Shop uses identical paths:** Juice Shop has a fixed dark purple/grey theme that does not change between light and dark browser settings. Providing the same image for both `light` and `dark` prevents the docs theme from showing a blank placeholder when the reader switches to dark mode.

**Why XC Console screenshots omit `dark=`:** The F5 XC Console does not offer a dark mode. There is no dark variant to capture, so `dark=` is intentionally omitted. The `<Screenshot>` component handles this gracefully.

---

## Architecture: Three Approaches

There are three fundamentally different approaches. Know which one you need:

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

1. Set exact viewport: `emulate` with viewport `"1600x900x1"` (the `x1` suffix forces deviceScaleFactor=1 — `resize_page` alone does NOT work on Retina displays)
2. Navigate and interact with the page as needed
   - **For theme variants**: call `emulate` with `colorScheme: "light"` before the light capture, then `colorScheme: "dark"` before the dark capture. See Section 13 for full details.
3. Call `take_screenshot` with a `filePath` to save directly to `docs/images/`
4. Use descriptive filenames matching the image alt text (e.g., `csd-lb-csd-settings.png`)
5. Verify: `sips -g pixelWidth -g pixelHeight docs/images/<name>.png` — must be exactly 1600x900
6. After all captures, reset: `emulate` with viewport `"0x0x0"` to restore defaults

### Approach B: System-Level UI Automation (osascript + screencapture)

For **visual screenshots of the DevTools UI** — showing filters, columns, panels, waterfall charts, etc. — you must use macOS system tools:

- `osascript` for keyboard/window management (requires Accessibility permissions)
- `/usr/sbin/screencapture` for window capture (requires Screen Recording permissions)
- Chrome profile `Preferences` file for pre-configuring DevTools settings

**Use this when you need an actual image of what the DevTools looks like.**

---

## Reproducibility Requirements

For identical screenshot outputs across different machines and sessions, the following must be true:

**Required for determinism:**

- macOS (any version with Chrome DevTools Protocol support)
- Google Chrome installed at `/Applications/Google Chrome.app`
- Node.js + globally-installed `ws` module
- Dedicated Chrome profile at `~/.cache/chrome-screenshot/chrome-profile` (fresh or reset before each session)
- No other Chrome instance using the same profile or debugging port
- Screen Recording permission granted (only for combined page+DevTools screenshots — Method 3)
- English locale (AppleScript window title detection depends on "DevTools"/"Developer Tools")

**Does NOT affect determinism:**

- Display resolution — `Emulation.setDeviceMetricsOverride` forces exact pixel dimensions regardless of physical display
- Window position — CDP screenshots capture the page target, not the screen
- macOS version — CDP interaction is OS-independent

---

## Prerequisites

### Required: Node.js + ws module

```bash
brew install node       # if not installed
npm install -g ws       # WebSocket library for CDP
```

When running CDP scripts: `NODE_PATH=$(npm root -g) node script.cjs`

### Screen Recording permission

**Required for combined page+DevTools screenshots** (Section 4, Method 3) — this is the most common use case when you need to show the page and a DevTools panel together. **Optional for CDP-only DevTools captures** (Method 1), which need no macOS permissions.

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
7. **Fully quit your terminal (Cmd+Q) and relaunch. A new tab is NOT sufficient** — macOS Screen Recording permissions take effect only when the parent process is freshly launched. Opening a new tab reuses the existing process tree and will not pick up the permission grant.

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

When running CDP scripts, use: `NODE_PATH=$(npm root -g) node script.cjs`

### Chrome profile for screenshots

These instructions use a **dedicated** Chrome profile directory at `~/.cache/chrome-screenshot/chrome-profile`. This MUST be separate from the `chrome-devtools-mcp` profile used by the MCP server. Chrome can only bind one process to a given `--user-data-dir` — if both the MCP server and the screenshot workflow use the same profile, one will fail with a lock error. Keep them separate.

**Reset to clean state** — use before any screenshot session where you need guaranteed-clean state (a stale profile with different DevTools settings will produce different screenshots):

```bash
rm -rf "$HOME/.cache/chrome-screenshot/chrome-profile"
mkdir -p "$HOME/.cache/chrome-screenshot/chrome-profile"
```

### CDP readiness polling (reusable pattern)

After launching Chrome, poll for CDP readiness before attempting any WebSocket connections. Use this canonical pattern everywhere:

```bash
# Poll for CDP readiness (max 30s)
for i in $(seq 1 30); do
    curl -sf http://localhost:9222/json/version > /dev/null 2>&1 && break
    sleep 1
done
curl -sf http://localhost:9222/json/version > /dev/null 2>&1 || { echo "ERROR: CDP not ready after 30s"; exit 1; }
```

### Chrome path

These instructions assume Chrome is installed at the default location:

```text
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
~/.cache/chrome-screenshot/chrome-profile/Default/Preferences
```

For standard Chrome (non-MCP):

```text
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

PREFS_PATH = "~/.cache/chrome-screenshot/chrome-profile/Default/Preferences"
# For standard Chrome:
# PREFS_PATH = "~/Library/Application Support/Google/Chrome/Default/Preferences"

# Full column schema — used to seed fresh profiles that have no network-log-columns yet
DEFAULT_COLUMNS = {
    "name": {"visible": True, "title": "Name"},
    "method": {"visible": False, "title": "Method"},
    "status": {"visible": True, "title": "Status"},
    "protocol": {"visible": False, "title": "Protocol"},
    "scheme": {"visible": False, "title": "Scheme"},
    "domain": {"visible": False, "title": "Domain"},
    "remote-address": {"visible": False, "title": "Remote Address"},
    "remote-address-space": {"visible": False, "title": "Remote Address Space"},
    "type": {"visible": True, "title": "Type"},
    "initiator": {"visible": True, "title": "Initiator"},
    "initiator-address-space": {"visible": False, "title": "Initiator Address Space"},
    "cookies": {"visible": False, "title": "Cookies"},
    "set-cookies": {"visible": False, "title": "Set-Cookies"},
    "size": {"visible": True, "title": "Size"},
    "time": {"visible": True, "title": "Time"},
    "priority": {"visible": False, "title": "Priority"},
    "connection-id": {"visible": False, "title": "Connection ID"},
    "cache-control": {"visible": False, "title": "Cache-Control"},
    "waterfall": {"visible": False, "title": "Waterfall"},
}

prefs_path = os.path.expanduser(PREFS_PATH)

with open(prefs_path) as f:
    prefs = json.load(f)

# Get current columns config (seed defaults on fresh profiles)
devtools_prefs = prefs.setdefault("devtools", {}).setdefault("preferences", {})
cols = json.loads(devtools_prefs.get("network-log-columns", "{}"))
if not cols:
    cols = DEFAULT_COLUMNS

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
# Enable domain and remote-address columns (add to existing, seed defaults on fresh profiles)
python3 -c "
import json, os
DEFAULT_COLUMNS = {
    'name': {'visible': True, 'title': 'Name'},
    'method': {'visible': False, 'title': 'Method'},
    'status': {'visible': True, 'title': 'Status'},
    'protocol': {'visible': False, 'title': 'Protocol'},
    'scheme': {'visible': False, 'title': 'Scheme'},
    'domain': {'visible': False, 'title': 'Domain'},
    'remote-address': {'visible': False, 'title': 'Remote Address'},
    'remote-address-space': {'visible': False, 'title': 'Remote Address Space'},
    'type': {'visible': True, 'title': 'Type'},
    'initiator': {'visible': True, 'title': 'Initiator'},
    'initiator-address-space': {'visible': False, 'title': 'Initiator Address Space'},
    'cookies': {'visible': False, 'title': 'Cookies'},
    'set-cookies': {'visible': False, 'title': 'Set-Cookies'},
    'size': {'visible': True, 'title': 'Size'},
    'time': {'visible': True, 'title': 'Time'},
    'priority': {'visible': False, 'title': 'Priority'},
    'connection-id': {'visible': False, 'title': 'Connection ID'},
    'cache-control': {'visible': False, 'title': 'Cache-Control'},
    'waterfall': {'visible': False, 'title': 'Waterfall'},
}
p = os.path.expanduser('~/.cache/chrome-screenshot/chrome-profile/Default/Preferences')
d = json.load(open(p))
dp = d.setdefault('devtools', {}).setdefault('preferences', {})
cols = json.loads(dp.get('network-log-columns', '{}'))
if not cols:
    cols = DEFAULT_COLUMNS
for c in ['domain', 'remote-address', 'waterfall']:
    if c in cols:
        cols[c]['visible'] = True
dp['network-log-columns'] = json.dumps(cols)
json.dump(d, open(p, 'w'))
print('Done')
"
```

### ⚠️ CRITICAL: Kill Chrome BEFORE editing preferences

Chrome writes preferences to disk on exit. If you edit the file while Chrome is running, your changes will be overwritten when Chrome shuts down. The correct order is:

```bash
# 1. Kill Chrome completely
pkill -9 -f "Google Chrome"

# 2. Poll until Chrome is fully terminated (max 10s)
for i in $(seq 1 10); do
    pgrep -f "Google Chrome" > /dev/null 2>&1 || break
    sleep 1
done
pgrep -f "Google Chrome" && echo "Still running - wait longer" || echo "Ready to edit"

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
p = os.path.expanduser('~/.cache/chrome-screenshot/chrome-profile/Default/Preferences')
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
p = os.path.expanduser('~/.cache/chrome-screenshot/chrome-profile/Default/Preferences')
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
p = os.path.expanduser('~/.cache/chrome-screenshot/chrome-profile/Default/Preferences')
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

# 2. Capture screenshot via CDP (script committed at scripts/cdp-screenshot.cjs)
NODE_PATH=$(npm root -g) node scripts/cdp-screenshot.cjs "$DEVTOOLS_WS" "devtools-screenshot.png"
```

> **Other capture scripts:** For Console panel screenshots, see Section 16. For a full catalogue of all committed helper scripts, see Section 17.

**After capture, verify dimensions (no resize needed — Emulation override produces exact 1280x720):**

```bash
sips -g pixelWidth -g pixelHeight devtools-screenshot.png
# Move to docs/images/ if correct
mv devtools-screenshot.png docs/images/devtools-screenshot.png
```

**Why this is better than screencapture:**

- No Screen Recording permission needed
- No `.app` wrapper needed
- Works reliably across process restarts (no TCC flakiness)
- Works headless (no window needs to be visible)
- `Emulation.setDeviceMetricsOverride` captures at exact 1280x720 — no post-capture resize, no aspect ratio distortion

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

### Method 3: Combined Page + DevTools Screenshot (`screencapture -l`)

CDP can only screenshot one target at a time — either the page or the DevTools UI, not both together. To capture a screenshot showing the page **and** docked DevTools side-by-side (e.g., page on the left, Network panel on the right), use macOS `screencapture` on the Chrome window.

**Requires:** Screen Recording permission (see Prerequisites).

**Workflow:**

1. **Set dock state in preferences** — set `currentDockState` to `"right"` (or `"bottom"`) in the Chrome profile Preferences file (Section 3). Do NOT use `"undocked"`.

2. **Launch Chrome** with `--auto-open-devtools-for-tabs` and `--remote-debugging-port=9222` (for any CDP interaction you need before capture).

3. **Find the Chrome window ID** using Swift:

   ```bash
   CHROME_WID=$(swift -e '
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
               if !name.contains("DevTools") && !name.contains("Developer Tools") {
                   print(id)
               }
           }
       }
   }
   ' 2>/dev/null | head -1)
   ```

4. **Capture the window** (includes both page and docked DevTools):

   ```bash
   /usr/sbin/screencapture -l "$CHROME_WID" -o -x /tmp/combined-screenshot.png
   ```

5. **Resize to standard dimensions:**

   ```bash
   sips -z 900 1600 /tmp/combined-screenshot.png --out docs/images/combined-screenshot.png
   sips -g pixelWidth -g pixelHeight docs/images/combined-screenshot.png
   ```

**Note:** On Retina displays, `screencapture` captures at 2x resolution. The `sips -z 900 1600` resize handles this automatically.

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

> **WARNING:** `document.dispatchEvent(new KeyboardEvent(...))` does **NOT** reliably open the DevTools Command Menu. DevTools keyboard shortcuts are handled above the DOM event layer — synthetic DOM events are ignored by the shortcut system. This approach may appear to work in some Chrome versions but fails silently in others.
>
> **Preferred approach:** Set the desired panel via the `panel-selected-tab` preference (see Section 3) before launching Chrome. This is deterministic and always works.

The following is documented for reference but should be considered a **best-effort fallback**, not a primary approach:

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

### Complete Node.js helper script

Save this as `devtools-interact.cjs` and run with `NODE_PATH=$(npm root -g) node devtools-interact.cjs`:

```javascript
const { WebSocket } = require('ws');

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

// WARNING: document.dispatchEvent(KeyboardEvent) does NOT reliably open
// the DevTools Command Menu. DevTools keyboard shortcuts are handled above
// the DOM event layer and synthetic DOM events are ignored. Prefer setting
// the panel via the `panel-selected-tab` preference (see Section 3) and
// restarting Chrome. Use this function only as a best-effort fallback.
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
  --user-data-dir="$HOME/.cache/chrome-screenshot/chrome-profile" \
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

### Example A: Pre-configure + CDP screenshot (RECOMMENDED)

Zero macOS permissions needed (captures DevTools only via CDP). Kill Chrome, configure preferences, relaunch with CDP, screenshot via CDP.

```bash
#!/bin/bash
set -e

TARGET_URL="${1:-https://example.com}"
OUTPUT="${2:-devtools-screenshot.png}"
PREFS="$HOME/.cache/chrome-screenshot/chrome-profile/Default/Preferences"

# 1. Kill Chrome completely (MUST be dead before editing preferences)
pkill -9 -f "Google Chrome" 2>/dev/null || true
# Poll until Chrome is fully terminated (max 10s)
for i in $(seq 1 10); do
    pgrep -f "Google Chrome" > /dev/null 2>&1 || break
    sleep 1
done
pgrep -f "Google Chrome" > /dev/null 2>&1 && { echo "ERROR: Chrome still running after 10s"; exit 1; }

# 2. Configure preferences
python3 << 'PYEOF'
import json, os

prefs_path = os.path.expanduser("~/.cache/chrome-screenshot/chrome-profile/Default/Preferences")
with open(prefs_path) as f:
    prefs = json.load(f)

dp = prefs.setdefault("devtools", {}).setdefault("preferences", {})

# Full column schema — seed defaults on fresh profiles
DEFAULT_COLUMNS = {
    "name": {"visible": True, "title": "Name"},
    "method": {"visible": False, "title": "Method"},
    "status": {"visible": True, "title": "Status"},
    "protocol": {"visible": False, "title": "Protocol"},
    "scheme": {"visible": False, "title": "Scheme"},
    "domain": {"visible": False, "title": "Domain"},
    "remote-address": {"visible": False, "title": "Remote Address"},
    "remote-address-space": {"visible": False, "title": "Remote Address Space"},
    "type": {"visible": True, "title": "Type"},
    "initiator": {"visible": True, "title": "Initiator"},
    "initiator-address-space": {"visible": False, "title": "Initiator Address Space"},
    "cookies": {"visible": False, "title": "Cookies"},
    "set-cookies": {"visible": False, "title": "Set-Cookies"},
    "size": {"visible": True, "title": "Size"},
    "time": {"visible": True, "title": "Time"},
    "priority": {"visible": False, "title": "Priority"},
    "connection-id": {"visible": False, "title": "Connection ID"},
    "cache-control": {"visible": False, "title": "Cache-Control"},
    "waterfall": {"visible": False, "title": "Waterfall"},
}

# Set desired columns (seed defaults on fresh profiles)
cols = json.loads(dp.get("network-log-columns", "{}"))
if not cols:
    cols = DEFAULT_COLUMNS
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
  --user-data-dir="$HOME/.cache/chrome-screenshot/chrome-profile" \
  --auto-open-devtools-for-tabs \
  --remote-debugging-port=9222 \
  --no-first-run \
  "$TARGET_URL" &>/dev/null &
disown

# 4. Wait for CDP to be ready (canonical polling pattern — see Prerequisites)
for i in $(seq 1 30); do
    curl -sf http://localhost:9222/json/version > /dev/null 2>&1 && break
    sleep 1
done
curl -sf http://localhost:9222/json/version > /dev/null 2>&1 || { echo "ERROR: CDP not ready after 30s"; exit 1; }

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

# Screenshot via committed script (scripts/cdp-screenshot.cjs)
NODE_PATH=$(npm root -g) node scripts/cdp-screenshot.cjs "$DEVTOOLS_WS" "$OUTPUT"

# 6. Verify dimensions (no resize needed — Emulation override produces exact 1280x720)
echo "Final dimensions:"
sips -g pixelWidth -g pixelHeight "$OUTPUT"
```

### Dismissing Juice Shop modals on fresh Chrome profiles

When using a fresh Chrome profile (as recommended), Juice Shop displays a welcome modal and a cookie consent banner on first load. These must be dismissed before taking screenshots.

**Automated dismissal via CDP** (add after page load, before screenshot):

```javascript
// Dismiss the welcome modal (close button)
await sendCDP(ws, 'Runtime.evaluate', {
    expression: `(function() {
        var btn = document.querySelector('.close-dialog, [aria-label="Close Welcome Banner"]');
        if (btn) btn.click();
    })();`,
    returnByValue: true
});
await new Promise(r => setTimeout(r, 500));

// Dismiss the cookie consent banner
await sendCDP(ws, 'Runtime.evaluate', {
    expression: `(function() {
        var btn = document.querySelector('.cc-dismiss, [aria-label="dismiss cookie message"]');
        if (btn) btn.click();
    })();`,
    returnByValue: true
});
await new Promise(r => setTimeout(r, 500));
```

In the Example A workflow, add these CDP calls to the **page target** (not the DevTools target) after navigating to the Juice Shop URL and before taking the screenshot. Find the page target by looking for a target whose URL does NOT contain `devtools_app.html`.

### Example B: Live CDP interaction — switch panel, set filter, screenshot

Use when Chrome is already running with `--remote-debugging-port=9222` and you need to change panels/filters dynamically. **No macOS permissions needed.**

This script sets `Emulation.setDeviceMetricsOverride` to 1280x720 at 1x DPR and replaces hardcoded `setTimeout` delays with polling for the command palette element.

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

# 2. Send command via CDP, then screenshot (script committed at scripts/cdp-interact.cjs)
NODE_PATH=$(npm root -g) node scripts/cdp-interact.cjs "$DEVTOOLS_WS" "$COMMAND" "$OUTPUT"
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

**Note:** This AppleScript approach matches window names using English strings ("DevTools", "Developer Tools"). It only works with English locale. For a locale-independent alternative, use CDP `Emulation.setDeviceMetricsOverride` to control the capture viewport directly — no window resizing needed.

```bash
# Set DevTools window to specific dimensions (uses AppleScript, English locale only)
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

# CDP alternative (locale-independent): use Emulation.setDeviceMetricsOverride
# to force exact viewport dimensions regardless of physical window size.
# Then screenshot via CDP — no window resizing needed.
```

---

## 9. Troubleshooting

### "could not create image from window" / "could not create image from display"

**Cause:** Screen Recording permission not granted for the process running `screencapture`.

**Fix:**

1. Create the Node.app wrapper (see Prerequisites, Step 1)
2. Add it to Screen Recording (see Prerequisites, Step 2)
3. **Fully quit your terminal (Cmd+Q) and relaunch** — a new tab is NOT sufficient. macOS permissions only take effect on freshly launched processes.

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

- `document.dispatchEvent(new KeyboardEvent(...))` does **NOT** reliably open the Command Menu or trigger DevTools shortcuts. DevTools handles shortcuts above the DOM event layer — synthetic DOM events are ignored.
- `Input.dispatchKeyEvent` alone also may not trigger DevTools shortcuts.
- **Preferred approach:** Set the desired panel via `panel-selected-tab` in the Chrome profile Preferences file (Section 3) before launching Chrome. This is deterministic and always works.
- The Command Menu dispatch is documented in Section 5 as a best-effort fallback only.

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

For new users setting up on a fresh Mac. Follow in order — Phase 2 ends with a mandatory terminal restart.

### Phase 1: Install

```bash
# 1. Install Node.js
brew install node  # if not already installed

# 2. Install ws (WebSocket library for CDP interaction)
npm install -g ws

# 3. Verify ws is accessible
NODE_PATH=$(npm root -g) node -e "require('ws'); console.log('ws OK')"

# 4. Create the screenshot Chrome profile directory
mkdir -p "$HOME/.cache/chrome-screenshot/chrome-profile"
```

### Phase 2: Permissions

```bash
# 5. Create Node.app wrapper for Screen Recording permission
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
echo "Created Node.app wrapper"

# 6. Grant Screen Recording permission
open "x-apple.systempreferences:com.apple.preference.security?Privacy_ScreenCapture"
echo "Click + -> Cmd+Shift+G -> ~/Applications/ -> select Node.app -> toggle ON"
```

**STOP: Fully quit your terminal (Cmd+Q) and relaunch.** A new tab is NOT sufficient — macOS permissions take effect only when the parent process is freshly launched.

### Phase 3: Verify (after terminal restart)

```bash
# 7. Verify screencapture works
/usr/sbin/screencapture -x /tmp/test-screenshot.png && echo "Screen capture OK" || echo "FAILED - check Screen Recording permission"

# 8. Verify Chrome is installed
ls "/Applications/Google Chrome.app" > /dev/null 2>&1 && echo "Chrome found" || echo "Install Google Chrome"

# 9. Smoke test: launch Chrome with CDP and verify connection
/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome \
  --user-data-dir="$HOME/.cache/chrome-screenshot/chrome-profile" \
  --remote-debugging-port=9222 \
  --no-first-run \
  "about:blank" &>/dev/null &
# Poll for CDP readiness (canonical pattern — see Prerequisites)
for i in $(seq 1 30); do
    curl -sf http://localhost:9222/json/version > /dev/null 2>&1 && break
    sleep 1
done
curl -sf http://localhost:9222/json/version && echo "CDP connection OK" || echo "FAILED - Chrome CDP not responding"
pkill -f "Google Chrome" 2>/dev/null || true

# 10. Note on Retina displays
echo "On Retina displays, CDP captures at native resolution (e.g., ~2824x1636)."
echo "DevTools: Emulation.setDeviceMetricsOverride captures at exact 1280x720 — no resize needed."
echo "screencapture: Resize 2x captures with sips -z 900 1600 <input> --out docs/images/<name>.png"
```

---

## 11. Screenshot Annotations (Badges/Labels)

Screenshots can be annotated with colored badge labels to highlight specific elements — for example, tagging scripts as "CSD Telemetry (sync)" or "Third-party" in a DevTools Elements panel screenshot.

This uses an HTML/CSS overlay approach: the screenshot becomes the background of an HTML page, badges are positioned with absolute CSS, and the result is captured via CDP at exact pixel dimensions. **No image editing tools needed.**

### Annotation tool: `scripts/annotate-screenshot.cjs`

Saved in the project at `scripts/annotate-screenshot.cjs` with its HTML template at `scripts/annotate-template.html`.

**Usage:**

```bash
NODE_PATH=$(npm root -g) node scripts/annotate-screenshot.cjs \
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
NODE_PATH=$(npm root -g) node scripts/annotate-screenshot.cjs \
  docs/images/raw-devtools-elements.png \
  docs/images/csd-injected-scripts.png \
  1280 720 \
  '[
    {"text":"CSD Telemetry (sync)","class":"badge-csd","centerY":108,"left":336},
    {"text":"Third-party","class":"badge-thirdparty","centerY":240,"left":680},
    {"text":"Third-party","class":"badge-thirdparty","centerY":258,"left":592},
    {"text":"CSD Telemetry (async)","class":"badge-csd","centerY":278,"left":592}
  ]'
```

> **Note:** The `centerY` and `left` values above are specific to the screenshot they were derived from. If you retake the source screenshot, re-measure all coordinates before re-annotating. See "Annotation coordinate fragility" below.

### Tips for positioning badges

1. **Take the screenshot first**, then open it in Preview or a browser to find the pixel coordinates for badge placement.
2. **Use `centerY` for vertical positioning.** Open the raw screenshot in Preview. Hover over the vertical center of the target row — the Y coordinate is your `centerY` value. No offset math needed.
3. **Coordinates are relative to the output dimensions** (e.g., 1280x720 for DevTools, 1600x900 for pages), not the source image's native resolution. The annotation tool scales the source image to fit.
4. **Place badges inline with the code/content they annotate** — typically to the right of the element, vertically centered on the line.
5. **Use `sips -g pixelWidth -g pixelHeight`** to verify the final annotated image is the correct dimensions.

### Annotation coordinate fragility

Badge coordinates are **per-capture, not universal**. Any change to the underlying screenshot invalidates all annotation positions. You must re-derive coordinates after retaking any source screenshot.

**Why coordinates break:**

- **SPA frameworks** (Angular, React, Vue) inject dynamic `<style>` elements at runtime. The number and order of these elements varies between page loads, changing the Elements panel tree layout between captures.
- **Browser updates** can shift DevTools rendering — font metrics, padding, row height, and scrollbar behavior all change across Chrome versions.
- **Target application updates** add, remove, or reorder DOM nodes, shifting everything below the change point in the Elements tree.
- **DevTools panel state** — different sidebar widths, drawer heights, or zoom levels change the coordinate space.

**Recommendations:**

- **Always re-measure after retake** — never reuse coordinates from a previous capture session.
- **Verify periodically** — even without retaking, spot-check that annotations still align after Chrome or target app updates.
- **Store raw screenshots** — keep un-annotated source images in the repo (or locally) so you can re-annotate without re-capturing.
- **Document coordinate derivation** — when annotating, note the Chrome version and capture date in a comment so future maintainers know when coordinates were last validated.

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

1. **Dual-resolution standard (both 16:9, 1x DPR).** Page screenshots: `emulate` with viewport `"1600x900x1"`. DevTools screenshots: `Emulation.setDeviceMetricsOverride` with `width: 1280, height: 720, deviceScaleFactor: 1` before `Page.captureScreenshot`. The smaller DevTools viewport makes text ~20% larger relative to the image. Always verify with `sips -g pixelWidth -g pixelHeight`.

2. **Use CDP when capturing a single target.** The CDP approach (Sections 4-5) requires zero macOS permissions and works well for isolated DevTools or page screenshots. However, CDP can only screenshot one target at a time. For **combined page+DevTools screenshots** (the most common use case), you must use `screencapture -l` (Method 3), which requires Screen Recording permission.

3. **The recommended workflow:**
   - Kill Chrome → edit preferences (columns, filters, dock state, panel) → relaunch with `--remote-debugging-port=9222 --auto-open-devtools-for-tabs`
   - For runtime interaction: CDP to open Command Menu, type commands, press Enter
   - Screenshot via CDP `Page.captureScreenshot` on the DevTools page target
   - `Emulation.setDeviceMetricsOverride` captures at exact 1280x720 — no resize needed
   - **No macOS permissions needed for any of this (DevTools-only captures)**

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

11. **`npm install -g ws` is required.** Run CDP scripts with `NODE_PATH=$(npm root -g) node script.cjs` to find the global module.

12. **Capture light and dark variants when possible.** Use `emulate` with `colorScheme: "light"` and `colorScheme: "dark"` to take both variants. Save with `-light.png` / `-dark.png` suffixes. Use the `Screenshot` component in MDX instead of Markdown `![]()` syntax. For sites without dark mode (F5 XC console), capture light only and use `<Screenshot light="..." alt="..." />`.

---

## 13. Light and Dark Mode Screenshots

### Overview

The docs-theme ships a `Screenshot` Astro component that auto-switches images based on the reader's selected theme. Authors should capture both light and dark variants when the target UI supports `prefers-color-scheme`. Some UIs (like the F5 XC console) are light-only — use a single-variant `Screenshot` for these.

### File naming convention

Use the `-light` / `-dark` suffix pattern:

- `<name>-light.png` — light mode variant
- `<name>-dark.png` — dark mode variant

Both go in `docs/images/`. Example: `csd-dashboard-light.png`, `csd-dashboard-dark.png`.

### MDX usage: the `Screenshot` component

Import the component and pass light/dark image paths:

```mdx
import Screenshot from '@f5-sales-demo/docs-theme/components/Screenshot.astro';

{/* Both variants */}
<Screenshot
  light="/images/csd-dashboard-light.png"
  dark="/images/csd-dashboard-dark.png"
  alt="CSD Dashboard showing summary cards and domain table"
/>

{/* Single variant — light only (site does not support dark mode) */}
<Screenshot
  light="/images/csd-lb-csd-settings.png"
  alt="CSD toggle and settings within the HTTP Load Balancer configuration"
/>

{/* Single variant — dark only */}
<Screenshot
  dark="/images/devtools-beacons-dark.png"
  alt="DevTools Network tab filtered to zeronaught"
/>
```

**Props:**

| Prop | Type | Required | Description |
| --- | --- | --- | --- |
| `light` | `string` | No\* | Path to light-mode image |
| `dark` | `string` | No\* | Path to dark-mode image |
| `alt` | `string` | Yes | Alt text for accessibility |
| `width` | `number` | No | Image width in pixels |
| `height` | `number` | No | Image height in pixels |

\*At least one of `light` or `dark` must be provided. When only one variant is provided, that image renders in both themes without swapping.

### Capturing light and dark page screenshots (chrome-devtools-mcp)

Use the `emulate` tool's `colorScheme` parameter to control `prefers-color-scheme`:

1. Set viewport: `emulate` with viewport `"1600x900x1"`
2. Navigate to the target page
3. **Light capture**: `emulate` with `colorScheme: "light"` then `take_screenshot` — save as `<name>-light.png`
4. **Dark capture**: `emulate` with `colorScheme: "dark"` then `take_screenshot` — save as `<name>-dark.png`
5. **Reset**: `emulate` with `colorScheme: "auto"` and viewport `"0x0x0"`

Sites that respect the `prefers-color-scheme` media query will switch their UI automatically. Sites that don't (like the F5 XC console) will look the same regardless — capture only a light variant for these.

### Capturing light and dark DevTools screenshots (CDP)

DevTools theme is controlled by the `uiTheme` preference in the Chrome profile:

```python
# Light DevTools theme
dp["uiTheme"] = '"default"'     # "default" = light theme

# Dark DevTools theme
dp["uiTheme"] = '"dark"'
```

**Workflow for both variants:**

1. Kill Chrome
2. Set `uiTheme` to `"default"` in preferences, launch Chrome, capture DevTools screenshot, save as `<name>-light.png`
3. Kill Chrome
4. Set `uiTheme` to `"dark"` in preferences, launch Chrome, capture DevTools screenshot, save as `<name>-dark.png`
5. Verify both are 1280x720 with `sips -g pixelWidth -g pixelHeight` (no resize needed with Emulation override)

### Combined page+DevTools screenshots in both themes

For combined screenshots (page + docked DevTools), both the page color scheme AND the DevTools theme need to match:

1. Kill Chrome
2. Set preferences: `uiTheme` = `"default"`, `currentDockState` = `"right"`
3. Launch Chrome, set page `colorScheme: "light"` via `emulate` or CDP
4. Capture with `screencapture -l` — save as `<name>-light.png`
5. Kill Chrome
6. Set preferences: `uiTheme` = `"dark"`, `currentDockState` = `"right"`
7. Launch Chrome, set page `colorScheme: "dark"` via `emulate` or CDP
8. Capture with `screencapture -l` — save as `<name>-dark.png`

### Decision guide: when to capture both variants

| Target UI | Dark mode support | Capture strategy |
| --- | --- | --- |
| Web apps respecting `prefers-color-scheme` | Yes | Both light + dark |
| F5 XC console | No | Light only |
| Chrome DevTools (standalone) | Yes | Both light + dark |
| Page + docked DevTools | Yes (both) | Both light + dark |
| Page (no dark) + docked DevTools | Mixed | Light only (DevTools dark would not match page) |

---

## 14. Collapsing DevTools Panels for Screenshots

When capturing Elements panel screenshots, the Styles sidebar and console drawer consume significant viewport space. Collapsing them gives the DOM tree the full width, producing cleaner screenshots. This section documents the techniques discovered and validated in commits `63bf891` and `0f656f4`.

### Why CSS hiding doesn't work

DevTools uses internal JavaScript sizing for its split panels. Setting `display: none` or `flex` overrides on sidebar/drawer elements via `Runtime.evaluate` leaves the main pane at its original pixel size — it does **not** expand to fill the freed space. The layout is controlled by `SplitWidget` internals, not CSS flow.

### SplitWidget API — collapsing the Styles sidebar

The correct approach uses the internal DevTools `SplitWidget` API, evaluated on the DevTools page target (`devtools_app.html`) via `Runtime.evaluate`:

```javascript
// Hide the Styles/Computed sidebar — DOM tree expands to full width
UI.panels.elements.splitWidget.hideSidebar();
```

This properly recalculates the internal layout so the DOM tree pane fills the entire viewport width.

To restore the sidebar:

```javascript
UI.panels.elements.splitWidget.showBoth();
```

**Important:** This must be evaluated on the DevTools target itself (the `devtools_app.html` page), not on the inspected web page. Use the DevTools WebSocket target identified by its `devtools://` or `chrome-devtools://` URL.

### Console drawer — close with Escape via CDP

The console drawer at the bottom of DevTools is toggled by the Escape key. Close it by dispatching key events via CDP `Input.dispatchKeyEvent` on the DevTools target:

```javascript
// Both keyDown and keyUp events are required
await sendCDP(ws, 'Input.dispatchKeyEvent', {
    type: 'keyDown', key: 'Escape', code: 'Escape',
    windowsVirtualKeyCode: 27, nativeVirtualKeyCode: 27
});
await sendCDP(ws, 'Input.dispatchKeyEvent', {
    type: 'keyUp', key: 'Escape', code: 'Escape',
    windowsVirtualKeyCode: 27, nativeVirtualKeyCode: 27
});
```

### Re-hiding after Elements panel search

When using Cmd+F to search in the Elements panel, pressing Escape to close the search bar can re-open the console drawer. Always re-apply panel collapsing after search operations:

```javascript
// After Cmd+F search → type query → Enter → Escape to close search:
// 1. Re-hide the sidebar (search may have restored it)
await evalOnDevTools(ws, 'UI.panels.elements.splitWidget.hideSidebar();');

// 2. Check if the drawer re-opened and press Escape again if needed
const drawerCheck = await evalOnDevTools(ws, `(function() {
    var d = document.querySelector('.drawer-tabbed-pane');
    if (d) { var r = d.getBoundingClientRect(); return 'h=' + Math.round(r.height); }
    return 'none';
})()`);
// If height > 5, press Escape again to close the drawer
```

### Verifying the drawer is closed

Use this snippet to check drawer visibility on the DevTools target:

```javascript
(function() {
    var d = document.querySelector('.drawer-tabbed-pane');
    if (d) {
        var r = d.getBoundingClientRect();
        return 'drawer h=' + Math.round(r.height);
    }
    return 'no drawer';
})()
```

- `no drawer` or `h=0` — drawer is closed
- `h=` greater than 5 — drawer is still visible, press Escape again

### Complete Elements panel screenshot workflow

This is the recommended sequence for capturing a clean Elements panel screenshot (references Section 4 for viewport setup and Section 5 for CDP interaction):

1. **Connect** to the DevTools WebSocket target (`devtools_app.html`)
2. **Set viewport**: `Emulation.setDeviceMetricsOverride` — 1280x720 at 1x DPR
3. **Force theme**: add/remove `theme-with-dark-background` class on the DevTools `<html>` element (see Section 13)
4. **Hide sidebar**: `UI.panels.elements.splitWidget.hideSidebar()`
5. **Close drawer**: dispatch Escape key events
6. **Search for target elements** (if needed): Cmd+F → type query → Enter → Escape. For a programmatic alternative that expands and selects specific DOM nodes without Cmd+F, see Section 15.
7. **Re-hide sidebar**: search may have restored it — call `hideSidebar()` again
8. **Re-check drawer**: verify height, press Escape again if visible
9. **Optional**: hide intermediate DOM nodes between search targets for a focused view. See Section 15 for the full DOM navigation technique (query selectors, tree expansion, scrolling).
10. **Capture**: `Page.captureScreenshot` with `format: 'png'`
11. **Verify dimensions**: `sips -g pixelWidth -g pixelHeight <output>` — confirm exactly 1280x720
12. **Verify content**: Open the PNG and confirm the sidebar/drawer are collapsed

**Drawer retry loop** — use this pattern when the drawer state is uncertain:

```javascript
// Retry closing the drawer up to 3 times
for (let attempt = 0; attempt < 3; attempt++) {
    const check = await evalOnDevTools(ws, `(function() {
        var d = document.querySelector('.drawer-tabbed-pane');
        if (d) { var r = d.getBoundingClientRect(); return Math.round(r.height); }
        return 0;
    })()`);
    if (check <= 5) break;
    // Press Escape to close
    await sendCDP(ws, 'Input.dispatchKeyEvent', {
        type: 'keyDown', key: 'Escape', code: 'Escape',
        windowsVirtualKeyCode: 27, nativeVirtualKeyCode: 27
    });
    await sendCDP(ws, 'Input.dispatchKeyEvent', {
        type: 'keyUp', key: 'Escape', code: 'Escape',
        windowsVirtualKeyCode: 27, nativeVirtualKeyCode: 27
    });
    await new Promise(r => setTimeout(r, 300));
}
```

> **Automation:** For automated sidebar/drawer collapsing with `<style>` tree item hiding, see `scripts/capture-csd-injected-scripts.cjs` (Section 17).

---

## 15. Elements Panel DOM Navigation

Programmatically navigating to specific DOM nodes in the Elements panel — expanding parent nodes, selecting elements, and scrolling the tree — requires DevTools-internal APIs evaluated on the `devtools_app.html` target. Standard CDP DOM methods do not control the Elements panel tree.

### 15.1 Why standard DOM inspection fails

Several approaches that seem like they should work do **not** reliably expand and select nodes in the Elements panel tree:

- **`SDK` is not a global in Chrome 145+.** Older examples using `SDK.DOMModel` or `SDK.DOMModel.requestDocument()` will throw `ReferenceError`. The `SDK` namespace was removed from the global scope.
- **`DOM.setInspectedNode`** on the page target sets `$0` in the Console but does **not** expand the Elements tree to show the node.
- **`inspect()` via `Runtime.evaluate`** on the page target opens the Elements panel but does **not** reliably expand the tree to reveal the inspected node.
- **`DOM.querySelector`** on the page target returns node IDs usable for data extraction but has no effect on the Elements panel UI.

The correct approach is to use the DevTools-internal `UI.panels.elements` API, evaluated on the DevTools page target (`devtools_app.html`) via `Runtime.evaluate`.

### 15.2 Accessing the DOM model (Chrome 145+)

The Elements panel exposes its tree outline and DOM model through internal APIs. Evaluate these on the DevTools target:

```javascript
// Get the tree outline and DOM model
const to = UI.panels.elements.getTreeOutlineForTesting();
const rootNode = to.rootDOMNodeInternal;
const dm = rootNode.domModel();

// Request the document root (async — returns a Promise)
const doc = await dm.requestDocument();

// Query for specific nodes by CSS selector
const nodeIds = await dm.querySelectorAll(doc.id, 'head > script[id]');
```

**Key objects:**

| Object | Access path | Description |
| --- | --- | --- |
| Tree outline | `UI.panels.elements.getTreeOutlineForTesting()` | Controls the visible DOM tree in the Elements panel |
| Root DOM node | `to.rootDOMNodeInternal` | The root of the inspected document's DOM model |
| DOM model | `rootNode.domModel()` | Provides `requestDocument()`, `querySelectorAll()`, `querySelector()` |
| Document node | `await dm.requestDocument()` | The `#document` node — pass its `id` to query methods |

### 15.3 Selecting and revealing DOM nodes

After obtaining node IDs from `querySelectorAll`, resolve them to DOM node objects and use the Elements panel API to select and reveal:

```javascript
// Resolve a nodeId to a DOMNode object
const node = dm.nodeForId(nodeId);

// Select the node — highlights it in the tree, sets == $0
UI.panels.elements.selectDOMNode(node, true);

// Reveal and select — expands all ancestor nodes, scrolls into view
const to = UI.panels.elements.getTreeOutlineForTesting();
await to.revealAndSelectNode(node, true);
```

**Behavior:**

- `selectDOMNode(node, true)` — selects the node and sets it as `$0` in the Console. The second parameter (`true`) means "focus the node".
- `revealAndSelectNode(node, true)` — expands all parent nodes (`<html>`, `<head>`, `<body>`, etc.) automatically, then scrolls the tree to bring the node into view. This is the most reliable way to make a specific node visible.

### 15.4 Scrolling the Elements tree (shadow DOM)

The Elements panel tree renders `<li>` elements inside a shadow DOM. Standard `document.querySelector` won't find them — you must query through the tree outline's shadow root:

```javascript
// Get all tree items via the shadow root
const to = UI.panels.elements.getTreeOutlineForTesting();
const items = to.shadowRoot.querySelectorAll('li');

// getBoundingClientRect() returns accurate viewport-relative positions
const rect = items[n].getBoundingClientRect();

// Scroll a specific item to the top of the visible tree area
items[n].scrollIntoView({ block: 'start', behavior: 'instant' });
```

**Tips:**

- Use `behavior: 'instant'` (not `'smooth'`) for deterministic positioning in screenshots.
- `getBoundingClientRect()` returns accurate viewport-relative coordinates even within shadow DOM.
- After scrolling, add a brief delay (100-200ms) before capturing to let the tree re-render.

### 15.5 Complete working example

This example connects to the DevTools target, queries for specific DOM nodes, selects and reveals them, collapses panels (Section 14), scrolls the tree, and captures a screenshot:

```javascript
// Run on the DevTools target (devtools_app.html) via Runtime.evaluate
// Assumes sendCDP() helper from scripts/cdp-interact.cjs

async function navigateAndCapture(ws) {
    // 1. Get the DOM model and query for target nodes
    const setupResult = await sendCDP(ws, 'Runtime.evaluate', {
        expression: `(async function() {
            const to = UI.panels.elements.getTreeOutlineForTesting();
            const rootNode = to.rootDOMNodeInternal;
            const dm = rootNode.domModel();
            const doc = await dm.requestDocument();

            // Example: find all <script> elements with an id attribute in <head>
            const nodeIds = await dm.querySelectorAll(doc.id, 'head > script[id]');
            return JSON.stringify(nodeIds);
        })()`,
        returnByValue: true,
        awaitPromise: true
    });
    const nodeIds = JSON.parse(setupResult.result.value);

    // 2. Select and reveal the first matching node
    await sendCDP(ws, 'Runtime.evaluate', {
        expression: `(async function() {
            const to = UI.panels.elements.getTreeOutlineForTesting();
            const dm = to.rootDOMNodeInternal.domModel();
            const node = dm.nodeForId(${nodeIds[0]});
            await to.revealAndSelectNode(node, true);
        })()`,
        returnByValue: true,
        awaitPromise: true
    });

    // 3. Collapse sidebar and drawer (Section 14)
    await sendCDP(ws, 'Runtime.evaluate', {
        expression: 'UI.panels.elements.splitWidget.hideSidebar();',
        returnByValue: true
    });

    // Close drawer via Escape
    await sendCDP(ws, 'Input.dispatchKeyEvent', {
        type: 'keyDown', key: 'Escape', code: 'Escape',
        windowsVirtualKeyCode: 27, nativeVirtualKeyCode: 27
    });
    await sendCDP(ws, 'Input.dispatchKeyEvent', {
        type: 'keyUp', key: 'Escape', code: 'Escape',
        windowsVirtualKeyCode: 27, nativeVirtualKeyCode: 27
    });

    // 4. Scroll the tree to position the target node at the top
    await sendCDP(ws, 'Runtime.evaluate', {
        expression: `(function() {
            const to = UI.panels.elements.getTreeOutlineForTesting();
            const items = Array.from(to.shadowRoot.querySelectorAll('li.selected'));
            if (items.length > 0) {
                items[0].scrollIntoView({ block: 'start', behavior: 'instant' });
            }
        })()`,
        returnByValue: true
    });

    // Brief delay for tree re-render
    await new Promise(r => setTimeout(r, 200));

    // 5. Capture screenshot
    await sendCDP(ws, 'Emulation.setDeviceMetricsOverride', {
        width: 1280, height: 720, deviceScaleFactor: 1, mobile: false
    });
    const screenshot = await sendCDP(ws, 'Page.captureScreenshot', { format: 'png' });
    return screenshot.data; // base64 PNG
}
```

**Usage with the CDP helper scripts:**

```bash
# 1. Find the DevTools target
DEVTOOLS_WS=$(curl -s http://localhost:9222/json | python3 -c "
import json, sys
for t in json.load(sys.stdin):
    if 'devtools_app.html' in t.get('url', ''):
        print(t['webSocketDebuggerUrl'])
        break
")

# 2. Run the navigation + capture (integrate into a .cjs script)
NODE_PATH=$(npm root -g) node your-dom-nav-script.cjs "$DEVTOOLS_WS" output.png
```

**Cross-references:**

- Section 14 — collapsing sidebar and drawer before capture
- Section 4, Method 1 — CDP screenshot fundamentals
- Section 5 — DevTools target discovery and CDP helpers
- Section 17 — `capture-csd-injected-scripts.cjs` implements this DOM navigation pattern end-to-end

---

## 16. Console Panel Screenshots

When you need to capture a screenshot showing script execution output in the DevTools Console panel (as opposed to Elements, Network, or Sources panels), use a different workflow. The Console panel has its own internal API surface and requires routing script execution through the Console prompt to produce visible output.

### When to use

- Capturing console.log output from attack/demo scripts (e.g., CDN injection, credential harvesting)
- Showing script execution results alongside their output messages
- Any screenshot where the Console panel (not Elements) is the primary content

### Why `prompt.appendCommand()` instead of `Runtime.evaluate`

`Runtime.evaluate` on the page target from an external CDP session does **not** produce visible `console.log` output in the DevTools Console panel.
The output goes to the CDP session's response, not the DevTools UI.
Using `prompt.appendCommand()` on the DevTools target routes the evaluation through the Console panel's own pipeline, so `console.log` output appears exactly as if the user pasted and ran the script.

### DevTools Console API surface

These APIs are evaluated on the DevTools target (`devtools_app.html`) via `Runtime.evaluate`:

```javascript
// Access the ConsoleView object
const view = UI.panels.console.view;

// Clear all console messages
view.clearConsole();

// Scroll viewport to the latest message
view.immediatelyScrollToBottom();

// Access the ConsolePrompt object
const prompt = view.prompt;

// Submit a command as if typed by the user
// The second parameter (true) means "use command line API"
prompt.appendCommand(scriptString, true);

// Get current prompt text
prompt.text();

// Clear prompt input
prompt.clear();
```

### Console error suppression

The demo site fires error-level console messages from two sources: `common.js` runtime errors and Bot Defense WebSocket reconnection failures (`wss://botdemo.sales-demo.f5demos.com/socket.io/...`). Additionally, injected CDN scripts from the attack simulation produce Chrome Issues (CORS, ES module errors). These create visible noise in Console screenshots:

- Red error messages in the Console panel
- An error counter badge (red square with count) in the top DevTools toolbar
- An "Issues" counter in both the top toolbar and Console toolbar

**Suppression strategy (three layers):**

1. **Message level filter** — The Console panel has a `messageLevelFiltersSetting` that controls which log levels are visible. Setting `error` and `warning` to `false` before clearing the console and executing scripts prevents error-level messages from ever registering. After execution, resetting to defaults restores the toolbar label from "Info only" to "Default levels".

```javascript
// Suppress errors and warnings (on DevTools target)
var f = UI.panels.console.view.filter;
f.messageLevelFiltersSetting.set({verbose: false, info: true, warning: false, error: false});

// ... clear console, execute script, wait ...

// Restore defaults (toolbar shows "Default levels" again)
f.messageLevelFiltersSetting.set({verbose: false, info: true, warning: true, error: true});
```

The preference key is `message-level-filters` (stored as JSON in Chrome Preferences). Default value: `{"verbose":false,"info":true,"warning":true,"error":true}`.

2. **Issue counter hiding** — The `devtools-issue-counter` custom element appears in both the Console toolbar and the main DevTools toolbar (inside the shadow DOM of `.main-tabbed-pane`). Hide both via `display: none`:

```javascript
// Hide issue counter in Console toolbar
var ci = document.querySelector('devtools-issue-counter');
if (ci) ci.style.display = 'none';

// Hide counters in the main toolbar (inside shadow DOM)
var pane = document.querySelector('.main-tabbed-pane');
var rt = pane.shadowRoot.querySelector('.tabbed-pane-right-toolbar');
var ic = rt.querySelector('devtools-issue-counter');
if (ic) ic.style.display = 'none';
```

3. **Error counter badge hiding** — The red error count badge is an `icon-button` element inside the same shadow DOM toolbar:

```javascript
var ib = rt.querySelector('icon-button');
if (ib) ib.style.display = 'none';
```

The attack script uses only `console.log` (info level), so all its output passes through the filter unaffected.

### Console drawer behavior

When the Console panel is the active panel (not a drawer), it shows a drawer bar at the bottom with tabs ("Console", "AI assistance", etc.). This bar appears in captures and cannot be hidden without switching to a different panel. Pressing Escape while the Console panel is active closes any sub-drawer but does not remove the tab bar itself.

### Complete Console panel screenshot workflow

This is the recommended sequence for capturing Console output screenshots. The committed script `scripts/capture-console-output.cjs` implements this workflow (see Section 17). Pass `""` as the script-file argument to capture a clean (empty) Console panel.

1. **Kill Chrome** — ensure clean state
2. **Set preferences** — `panel-selected-tab` = `console`, `currentDockState` = `undocked`, `uiTheme` = `"default"` or `"dark"` (Section 3)
3. **Launch Chrome** with `--remote-debugging-port=9222` and navigate to the target page
4. **Connect to both targets**:
   - **Page target** — for cookie banner dismissal and credential filling
   - **DevTools target** (`devtools_app.html`) — for Console API interaction and screenshot capture
5. **Page target: dismiss cookie banner** — click `.cc-dismiss` or equivalent
6. **Page target: fill credentials** — populate email/password fields so the page is in a realistic state
7. **DevTools target: set viewport** — `Emulation.setDeviceMetricsOverride` at 1280x720, 1x DPR
8. **DevTools target: force theme** — add/remove `theme-with-dark-background` class (Section 13)
9. **DevTools target: suppress errors** — set `messageLevelFiltersSetting` to hide error/warning levels
10. **DevTools target: clear console** — `UI.panels.console.view.clearConsole()`
11. **DevTools target: execute script** (if provided) — `UI.panels.console.view.prompt.appendCommand(script, true)`
12. **Wait for async callbacks** — 5-6 seconds for network requests, dynamic script loads, and fetch completions
13. **DevTools target: restore default filters** — reset `messageLevelFiltersSetting` to defaults
14. **DevTools target: close drawer** — press Escape via `Input.dispatchKeyEvent` to close any sub-drawer
15. **DevTools target: scroll to bottom** — `UI.panels.console.view.immediatelyScrollToBottom()`
16. **DevTools target: hide error/issue badges** — hide `icon-button` and `devtools-issue-counter` in both toolbars
17. **Capture** — `Page.captureScreenshot` with `format: 'png'` on the DevTools target
18. **Verify** — confirm 1280x720 dimensions and visible console output

**Cross-references:**

- Section 3 — Chrome preferences for panel selection and theme
- Section 4, Method 1 — CDP screenshot fundamentals
- Section 5 — DevTools target discovery
- Section 13 — theme switching
- Section 17 — `capture-console-output.cjs` script reference

---

## 17. Committed Helper Scripts Reference

The `scripts/` directory contains 5 committed Node.js scripts (plus one HTML template) for CDP-based screenshot capture and annotation. All scripts require the `ws` npm package available via `NODE_PATH=$(npm root -g)`.

### 17.1 `cdp-screenshot.cjs` — Basic DevTools screenshot

**Purpose:** Connect to a DevTools target, set viewport to 1280x720, capture a PNG screenshot.

**Usage:**

```bash
NODE_PATH=$(npm root -g) node scripts/cdp-screenshot.cjs <ws-url> [output-path]
```

**Parameters:**

| Parameter | Required | Description |
| --- | --- | --- |
| `ws-url` | Yes | WebSocket URL of the DevTools target |
| `output-path` | No | Output PNG path (default: `devtools-screenshot.png`) |

**Prerequisites:** Chrome running with `--remote-debugging-port=9222`. Target panel and theme should be pre-configured via preferences (Section 3).

**Cross-references:** Section 4 Method 1, Section 5

### 17.2 `cdp-interact.cjs` — Command Menu interaction

**Purpose:** Open the DevTools Command Menu (Cmd+Shift+P), type a command, execute it, then capture a screenshot.

**Usage:**

```bash
NODE_PATH=$(npm root -g) node scripts/cdp-interact.cjs <ws-url> <command> <output-path>
```

**Parameters:**

| Parameter | Required | Description |
| --- | --- | --- |
| `ws-url` | Yes | WebSocket URL of the DevTools target |
| `command` | Yes | Command Menu text to type (e.g., `"Show Network"`) |
| `output-path` | Yes | Output PNG path |

**Caveat:** `document.dispatchEvent(KeyboardEvent)` does not reliably open the Command Menu — DevTools shortcuts are handled above the DOM event layer. Prefer setting the panel via preferences (Section 3) and restarting Chrome. This script is a best-effort fallback.

**Cross-references:** Section 3, Section 4 Method 1

### 17.3 `annotate-screenshot.cjs` — Badge annotations

**Purpose:** Overlay badge annotations (labels, callouts) on an existing screenshot PNG using an HTML template rendered via CDP.

**Usage:**

```bash
NODE_PATH=$(npm root -g) node scripts/annotate-screenshot.cjs \
  <screenshot> <output> <width> <height> '<badges-json>'
```

**Parameters:**

| Parameter | Required | Description |
| --- | --- | --- |
| `screenshot` | Yes | Path to the source screenshot PNG |
| `output` | Yes | Path for the annotated output PNG |
| `width` | Yes | Viewport width (typically `1280`) |
| `height` | Yes | Viewport height (typically `720`) |
| `badges-json` | Yes | JSON array of badge objects |

**Badge object format:**

```json
[
  {
    "text": "CSD Script",
    "class": "badge-csd",
    "centerY": 110,
    "left": 500
  }
]
```

Available badge classes: `badge-csd`, `badge-thirdparty`, `badge-info`, `badge-warning`, `badge-success`.

**Template:** Uses `scripts/annotate-template.html` for rendering. The template defines badge styles, positioning, and the background screenshot overlay.

**Prerequisites:** Chrome running with `--remote-debugging-port=9222` and at least one page target available.

**Cross-references:** Section 4 Method 1

### 17.4 `capture-csd-injected-scripts.cjs` — Elements panel with style hiding

**Purpose:** Capture an Elements panel screenshot showing the three CSD-injected `<script>` tags in `<head>`, with intermediate `<style>` tree items hidden and the Styles sidebar and console drawer collapsed.

**Usage:**

```bash
NODE_PATH=$(npm root -g) node scripts/capture-csd-injected-scripts.cjs \
  <ws-url> [output-path] [light|dark]
```

**Parameters:**

| Parameter | Required | Description |
| --- | --- | --- |
| `ws-url` | Yes | WebSocket URL of the DevTools target |
| `output-path` | No | Output PNG path (default: `/tmp/csd-injected-scripts-raw.png`) |
| `light\|dark` | No | Theme (default: `light`) |

**What the script does (end-to-end):**

1. Sets viewport to 1280x720 at 1x DPR
2. Forces light or dark theme via `theme-with-dark-background` class
3. Collapses Styles sidebar: `UI.panels.elements.splitWidget.hideSidebar()`
4. Closes console drawer via Escape key events (with retry loop)
5. Queries DOM model for three target scripts:
   - CSD sync: `head > script[src*="common.js"]` with `single` in src
   - Bot Defense: `head > script[src*="bot_defense"]`
   - CSD async: `head > script[async]`
6. Reveals and selects each script node via `to.revealAndSelectNode(node, true)`
7. Re-hides sidebar and drawer (reveal operations can restore them)
8. Hides `<style>` tree items between script 1 and script 3 via `display: none`
9. Scrolls script 1 to top of visible area
10. Re-hides sidebar one final time
11. Captures screenshot

**DevTools APIs used:** `UI.panels.elements.splitWidget`, `UI.panels.elements.getTreeOutlineForTesting()`, `to.rootDOMNodeInternal.domModel()`, `dm.requestDocument()`, `dm.querySelectorAll()`, `dm.nodeForId()`, `to.revealAndSelectNode()`.

**Prerequisites:** Chrome with the target page loaded in Elements panel. The page must have the three CSD-injected scripts in `<head>`.

**Cross-references:** Section 14 (sidebar/drawer collapsing), Section 15 (DOM navigation APIs)

### 17.5 `capture-console-output.cjs` — Console panel screenshot

**Purpose:** Capture a Console panel screenshot, optionally executing an attack/demo script via the Console prompt API first. Includes error suppression to hide demo site noise.

**Usage:**

```bash
# With script execution
NODE_PATH=$(npm root -g) node scripts/capture-console-output.cjs \
  <page-ws> <devtools-ws> <script-file> <output-path> [light|dark]

# Clean console (no script)
NODE_PATH=$(npm root -g) node scripts/capture-console-output.cjs \
  <page-ws> <devtools-ws> "" <output-path> [light|dark]
```

**Parameters:**

| Parameter | Required | Description |
| --- | --- | --- |
| `page-ws` | Yes | WebSocket URL of the page target |
| `devtools-ws` | Yes | WebSocket URL of the DevTools target |
| `script-file` | Yes | Path to JS file to execute, or `""` for clean console |
| `output-path` | No | Output PNG path (default: `/tmp/console-output.png`) |
| `light\|dark` | No | Theme (default: `light`) |

**Why two WebSocket connections:** The script needs the page target to dismiss the cookie banner and fill credentials, and the DevTools target to interact with the Console panel UI and capture the screenshot.

**What the script does (end-to-end):**

1. Connects to both the page and DevTools targets
2. Page target: dismisses cookie banner (`.cc-dismiss`)
3. Page target: fills email and password fields
4. DevTools target: sets viewport to 1280x720 at 1x DPR
5. DevTools target: forces theme
6. DevTools target: suppresses error/warning levels via `messageLevelFiltersSetting`
7. DevTools target: clears console via `UI.panels.console.view.clearConsole()`
8. DevTools target: executes script (if provided) via `prompt.appendCommand(script, true)`
9. Waits 6 seconds for async callbacks (network requests, dynamic script loads)
10. DevTools target: restores default level filters
11. DevTools target: closes drawer via Escape
12. DevTools target: scrolls to bottom via `view.immediatelyScrollToBottom()`
13. DevTools target: hides error/issue badges via DOM manipulation (shadow DOM)
14. Captures screenshot on DevTools target

**DevTools APIs used:** `UI.panels.console.view`, `view.clearConsole()`, `view.immediatelyScrollToBottom()`, `view.filter.messageLevelFiltersSetting`, `view.prompt`, `prompt.appendCommand()`.

**Prerequisites:** Chrome with the target page loaded, DevTools open to Console panel (set via preferences — Section 3). The script file should contain the JavaScript to execute (e.g., a CDN injection attack script).

**Cross-references:** Section 16 (Console panel workflow, error suppression), Section 3 (Chrome preferences), Section 13 (theme switching)
