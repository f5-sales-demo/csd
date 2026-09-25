# CSD — Walkthrough Configuration

## Demo App

AWS reference: <https://client-side-defense.f5-sales-demo.com> — Juice Shop behind one unsuffixed `client-side-defense` F5 Distributed Cloud HTTP load balancer. It terminates HTTPS with an automatic certificate, redirects HTTP to HTTPS, routes to an AWS ALB hostname through a `public_name` origin, and injects CSD on all pages.

Azure alternate: use the `LB_FQDN` output from the separately owned `webapp-api-protection` deployment; its origin pool uses `public_ip`. Do not present the Azure alternate as part of the AWS reference topology.

Choose one ownership mode. Never run the API create/update/delete workflow against resources present in Terraform state.

## Walkthrough Order

At each step: **(1) show the screen**, **(2) narrate what we're looking
at in plain language**, **(3) connect it to the customer's concern**,
**(4) pause for questions** before moving on.

1. **Overview** (`docs/en/overview.mdx`) — explain the one-LB path, AWS reference, Azure alternate, and mutually exclusive API/Terraform ownership.
2. **XC Configuration** (`docs/en/xc-configuration.mdx`) — show the unsuffixed LB, HTTPS automatic certificate with redirect, public default VIP, one route pool, and all-pages CSD injection.
3. **Demo App** (`docs/en/demo-website.mdx`) — open the AWS Juice Shop reference and orient the customer.
4. **Proof chain** (`docs/en/diagnostics.mdx`) — confirm ECS steady state, healthy ALB target, log delivery, ready F5 virtual host, valid certificate, HTTP `301`, HTTPS `200`, and rendered Juice Shop.
5. **Telemetry Beacons** (`docs/en/telemetry-beacons.mdx`) — show the injected `__imp_apg__` script and a browser `dip` request.
6. **Trigger Detection** (`docs/en/trigger-detection.mdx`) — run `scripts/csd-traffic.mjs`, then inspect the sanitized Page/Runtime/Network/Log receipt, terminal outcomes, instrumentation evidence, and cleanup.
7. **CSD Console** (`docs/en/csd-console.mdx`) — only after the receipt passes, query or show asynchronous CSD telemetry and label it observed, not observed, pending, or error without promising timing.
8. **Terraform closeout, when Terraform owns the stack** (`docs/en/terraform/index.mdx`) — show a final refresh-aware plan with no drift.

Supporting pages: `docs/en/attack-scripts.mdx`, `docs/en/diagnostics.mdx`, `docs/en/demo/`, `docs/en/api-reference.mdx`, and `docs/en/references.mdx`.

## Attack / Trigger Simulation

Use the canonical scenario module and CLI; do not paste copied payloads from documentation:

```bash
node scripts/csd-traffic.mjs --list
mkdir -p .artifacts/csd
node scripts/csd-traffic.mjs \
  --scenario maximum-detection \
  --cdp-endpoint http://127.0.0.1:9222 \
  --timeout 30s \
  --settle 10s \
  --receipt .artifacts/csd/walkthrough-maximum-detection.json
jq '{schema_version, run_id, started_at, ended_at, duration_ms, tool,
  requested_scenarios, target, allowlist, cdp_endpoint,
  scenarios: [.scenarios[] | {name, target, status, immediate_evidence, dom_cleanup, console, network, protected_document, instrumentation, cleanup, error, success, eventual_csd_evidence}],
  success, caveats, error, eventual_csd_evidence}' \
  .artifacts/csd/walkthrough-maximum-detection.json
```

`--scenario` is repeatable; use `--all` instead when all 11 scenarios are required. There is no
implicit execution selector. `--timeout` and `--settle` are browser-operation/event-collection
durations, not platform timing promises. With `--receipt -`, stdout contains only the JSON receipt
and human logs use stderr. A requested receipt is written atomically even after execution or cleanup
failure, preserving the primary error separately from cleanup errors.

Chrome or Chromium must expose a loopback CDP endpoint. A custom target requires `--target` and exact repeatable `--allow-host` values; redirects and final documents outside the exact allowlist fail closed.

For manual fallback, generate the reviewed payload with `node scripts/csd-traffic.mjs --print-script maximum-detection`; this canonical output is the only payload source. The receipt must retain sanitized Log/console evidence and real Network terminal outcomes. In particular, `high-volume-domain-exfiltration` is five script attempts plus two POST attempts, not volumetric traffic.

The runner does not query platform APIs. Only after the immediate receipt passes, run separate read-only `xcsh_api` operations scoped to its time window, protected origin, and reviewed Network hosts. Keep `eventual_csd_evidence` null/separate until then, report only observed subsets, and promise no detection timing or complete classification.

## Screenshot Standards

| Type                        | Dimensions | DPR | Format |
| --------------------------- | ---------- | --- | ------ |
| Page (XC console, web app)  | 1600 x 900 | 1x  | PNG    |
| DevTools (console, network) | 1280 x 720 | 1x  | PNG    |

### Dark Mode Conventions

| Source     | Pattern                                                               |
| ---------- | --------------------------------------------------------------------- |
| XC Console | Light only — `light="..."` (no `dark=`)                               |
| Juice Shop | Same image both modes — `light="..." dark="..."` with identical paths |
| DevTools   | Light/dark pairs — `*-light.png` / `*-dark.png`                       |

### Existing Screenshot Qualification

Until recaptured, every screenshot referenced by `docs/en/xc-configuration.mdx`,
`docs/en/demo-website.mdx`, and `docs/en/csd-console.mdx` is a layout-only orientation aid.
Do not present screenshot values, rows, counts, timestamps, classifications, script paths, or controls
as current tenant evidence. Verify the corresponding live view during the walkthrough, including the
DevTools Elements view used to prove injected scripts.
