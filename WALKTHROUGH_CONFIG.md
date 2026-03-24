# CSD — Walkthrough Configuration

## Demo App

<https://botdemo.sales-demo.f5demos.com> — Juice Shop running behind
an F5 XC HTTP Load Balancer

## Walkthrough Order

At each step: **(1) show the screen**, **(2) narrate what we're looking
at in plain language**, **(3) connect it to the customer's concern**,
**(4) pause for questions** before moving on.

1. **Overview** (`overview.mdx`) — set context: what client-side
   attacks are and why they're hard to see
2. **XC Configuration** (`xc-configuration.mdx`) — show how CSD is
   wired to the load balancer
3. **Demo App** (`demo-website.mdx`) — orient the customer to the
   Juice Shop app
4. **Telemetry Beacons** (`telemetry-beacons.mdx`) — show the injected
   scripts and beacon traffic in DevTools
5. **Trigger Detection** (`trigger-detection.mdx`) — run an attack
   script, explain what just happened
6. **CSD Console** (`csd-console.mdx`) — show detections appearing
   after the attack

Supporting pages: `attack-scripts.mdx`, `diagnostics.mdx`,
`demo/`, `api-reference.mdx`, `references.mdx`

## Attack / Trigger Simulation

Paste IIFE scripts from `docs/attack-scripts.mdx` into the browser
DevTools Console. The combined detection script in
`docs/trigger-detection.mdx` provides a three-phase simulation
(harvest → inject → exfiltrate) that triggers all three detection
signals.

For AI-automated execution, use the `initScript` harness from
`docs/trigger-detection.mdx` which handles zone.js incompatibility
in the Angular-based Juice Shop.

## Detection Timing

Detection takes **5-10 minutes** to appear in the CSD dashboard after
running scripts. Plan the walkthrough accordingly — run the attack
simulation early, then continue with other walkthrough steps while
waiting for detections to appear.

## Screenshot Standards

| Type | Dimensions | DPR | Format |
| ---- | ---------- | --- | ------ |
| Page (XC console, web app) | 1600 x 900 | 1x | PNG |
| DevTools (console, network) | 1280 x 720 | 1x | PNG |

### Dark Mode Conventions

| Source | Pattern |
| ------ | ------- |
| XC Console | Light only — `light="..."` (no `dark=`) |
| Juice Shop | Same image both modes — `light="..." dark="..."` with identical paths |
| DevTools | Light/dark pairs — `*-light.png` / `*-dark.png` |
