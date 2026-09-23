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
6. **Trigger Detection** (`docs/en/trigger-detection.mdx`) — run the authorized simulation and explain the observed signals.
7. **CSD Console** (`docs/en/csd-console.mdx`) — show detections after the documented observation window.
8. **Terraform closeout, when Terraform owns the stack** (`docs/en/terraform/index.mdx`) — show a final refresh-aware plan with no drift.

Supporting pages: `docs/en/attack-scripts.mdx`, `docs/en/diagnostics.mdx`, `docs/en/demo/`, `docs/en/api-reference.mdx`, and `docs/en/references.mdx`.

## Attack / Trigger Simulation

Paste IIFE scripts from `docs/en/attack-scripts.mdx` into the browser DevTools Console. The combined detection script in `docs/en/trigger-detection.mdx` provides a three-phase simulation (harvest → inject → exfiltrate) that triggers all three detection signals.

For AI-automated execution, use the `initScript` harness from `docs/en/trigger-detection.mdx`, which handles zone.js incompatibility in the Angular-based Juice Shop. Treat resulting detections, script injection, and beacon traffic as observed lab evidence rather than guaranteed timing or behavior in another tenant.

## Detection Timing

In this lab, detections have typically appeared in the CSD dashboard within **5-10 minutes** after
running scripts. This is a lab-observed polling window, not a service-level objective; timing and
classification are tenant-dependent. Run the simulation early, continue with other walkthrough
steps while polling, and troubleshoot rather than claiming success if the bounded window expires.

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
