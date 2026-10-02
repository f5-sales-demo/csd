# CSD — Readiness Verification Matrix

## Deployment Contract

The AWS reference and Azure alternate use the same logical F5 Distributed Cloud architecture: namespace `client-side-defense`, domain `client-side-defense.f5-sales-demo.com`, one origin pool, and one unsuffixed `client-side-defense` HTTP load balancer. The LB uses HTTPS automatic certificates with HTTP redirect, the public default VIP, one default route-pool reference, and CSD injection on all pages.

The reference origin can be a hostname via `public_name` or an IP via `public_ip`; healthcheck attachment is optional. API mode receives this origin as independent input and never reads Terraform or AWS state.

Choose one ownership mode. `XCSH_CSD_DEPLOYMENT_MODE` must be exactly `api` or `terraform`. Never run the API create/update/delete workflow against resources present in Terraform state.

For API-owned execution, resolve the tenant API URL and token, namespace, domain, unsuffixed LB
name, origin-pool name, origin kind, exactly one matching non-placeholder hostname or IP, and an
integer port from 1 through 65535. The unselected origin value must be empty, and an empty
`XCSH_HC_NAME` means omit the healthcheck. Reject example credentials, `origin.example.com`, and
RFC 5737 TEST-NET addresses. Always require a non-empty, non-placeholder
`XCSH_APPLICATION_MARKER`, independent of origin representation. The repository reference defaults
to `OWASP Juice Shop`; non-reference API and Azure scenarios must set a stable scenario marker.

## Readiness Checks

### T0: Connectivity & Auth

FAIL in any T0 check blocks all subsequent tiers. WARN in T0 (e.g.,
namespace does not exist) does **not** block — the demo can proceed
and Phase 1 Step 0 will create the namespace. Each check captures the
HTTP status code and pipes it through a jq filter that computes a
deterministic `{check, http_code, status, detail}` object — no
operator interpretation required.

1. **PF-T0-1: API Connectivity** — GET `/api/web/namespaces` with
   `--connect-timeout 10 --max-time 15`. jq computes: `200` → PASS,
   `401` → FAIL (token invalid), `0` → FAIL (network unreachable —
   try `--tlsv1.2 --tls-max 1.2`), all others → FAIL.
2. **PF-T0-2: Namespace Access** — GET
   `/api/config/namespaces/{namespace}/http_loadbalancers`. jq
   computes: `200` → PASS, `403` → FAIL (missing role binding),
   `404` → WARN (namespace does not exist — will be created in
   Phase 1 Step 0), all others → FAIL.
3. **PF-T0-3: CSD API Access** — GET
   `/api/shape/csd/namespaces/{namespace}/status`. jq computes:
   `200` → PASS, `403` → FAIL (missing CSD role binding), `404`
   → WARN (namespace does not exist — CSD access will be verified
   after namespace creation in Phase 1), all others → FAIL.
4. **PF-T0-4: Read-Only Access Matrix** — establish ownership first, then
   use GET requests on the namespace and required list/detail endpoints.
   `XCSH_CSD_DEPLOYMENT_MODE` must be exactly `api` or `terraform`. API mode
   classifies each target as absent, pre-existing, or unknown; Terraform
   mode stops this API workflow and uses only its configured backend and
   state. A successful read proves visibility, not write permission.
   Never test authorization with DELETE, namespace cascade deletion, or
   another mutation. Required-resource `403` responses fail readiness;
   unresolved ownership or unexpected responses are UNKNOWN and block
   mutation.

### T1: Quotas & Capacity

Uses the read-only Quota Usage API to query tenant-wide limits and
current usage for each object kind the demo needs. Calculates remaining
capacity and reports PASS/WARN/FAIL when the endpoint provides complete
data. If access is denied or a required kind is absent, record capacity
as UNKNOWN and obtain an administrator quota/configuration check; do not
create temporary objects.

The gate evaluates the required platform object capacity:

| Kind                | Needed | Required | Min to proceed |
| ------------------- | ------ | -------- | -------------- |
| `healthcheck`       | 1      | No       | 0              |
| `origin_pool`       | 1      | Yes      | 1              |
| `endpoint`          | 1      | Yes      | 1              |
| `http_loadbalancer` | 1      | Yes      | 1              |

For each kind, the jq filter calculates:

- `remaining = limit - usage` (unlimited if limit is `-1`)
- `status = PASS` if `remaining >= needed`
- `status = WARN` if `remaining >= min_proceed` but `< needed`
- `status = FAIL` if `remaining < min_proceed` and kind is required (WARN if optional)

The overall `gate` is FAIL if any check is FAIL, WARN if any is WARN, PASS otherwise. A FAIL gate blocks demo execution.

1. **PF-T1-4: Protected Domain Capacity** — protected-domain capacity is
   not exposed by the platform Quota Usage API. List current protected
   domains to detect target conflicts, then record capacity as UNKNOWN
   unless an administrator supplies the limit and usage. Do not create
   or delete a probe, and never treat `409` as proof of available quota.

### Exceptional Mutation Probes

Readiness has no mutation fallback. If an exceptional mutation probe is
separately approved, it must use a run-unique DNS-label name, prove that
exact name absent with GET, and atomically append every GET and POST
result to the ownership ledger. Only a ledger entry marked `created` may
be deleted. A `409` is `pre-existing`, never `created`.

### T2: Platform Prerequisites

FAIL in any T2 check blocks execution. Each check computes a
deterministic `{check, status, detail}` object via jq.

1. **PF-T2-1: CSD Tenant Status** — GET CSD status. jq computes:
   `{check, configured, enabled, status, detail}` where `status` is
   PASS if both `.isConfigured` and `.isEnabled` are `true`, FAIL
   otherwise.
2. **PF-T2-2: DNS Zone Exists** — GET
   `/api/config/dns/namespaces/system/dns_zones/{root_domain}`.
   HTTP code captured in variable, jq computes: `200` → PASS,
   `404` → WARN (external DNS may be in use), `403` → WARN (token
   may lack system namespace access), all others → FAIL.
3. **PF-T2-3: DNS Managed Records** — only if T2-2 returned `200`.
   Read and report `spec.primary.allow_http_lb_managed_records`. `true`
   is PASS; `false` or absent is WARN. Never automatically PUT a shared
   DNS zone. Use external/manual DNS, or obtain separate approval from
   the established DNS owner for a reviewed complete-spec change.
4. **PF-T2-4: DNS Nameserver Authority** — `dig +short NS`
   output piped through `jq -Rs` which computes:
   `{check, nameservers, status, detail}` where `status` is PASS
   if output contains `f5clouddns.com`, INFO for external DNS,
   FAIL if no NS records found.

### T3: Origin Health

Resolve the API origin from independent environment input, never from Terraform or AWS state.
Require `XCSH_ORIGIN_KIND=public_name|public_ip`, exactly one matching non-placeholder hostname or
IP, the other value empty, and an integer `XCSH_ORIGIN_PORT` from 1 through 65535. Empty
`XCSH_HC_NAME` means omit the healthcheck. Always require `XCSH_APPLICATION_MARKER` to be non-empty
and not a documentation placeholder. The repository reference defaults to `OWASP Juice Shop`;
non-reference API and Azure scenarios must set a stable, deployment-specific marker.

`XCSH_CSD_DEPLOYMENT_MODE=api|terraform` identifies ownership only and must not select cloud-provider checks.

1. **PF-T3-1: Origin Connectivity** — request the resolved origin with bounded connect and total timeouts. A valid HTTP response proves reachability; connection failure blocks end-to-end proof.
2. **PF-T3-2: Origin Content** — require the stable `XCSH_APPLICATION_MARKER` value in the origin response regardless of origin representation. Record the matching response as an observed lab result; a status code alone is not content proof.

### T4: Ownership and Existing State

Determine the owner before any mutation. API mode expects targets to be absent or recorded in the current run's atomic ledger. The ledger permits only approved kinds and stores exact name, namespace, and one status (`created`, `pre-existing`, or `unknown`), with exactly one entry per kind/name/namespace.

Append after every GET and POST result. `409` is always `pre-existing`. Phase 3 records mitigated domains.

Phase 4 derives targets only from ledger entries marked `created`, fails on API URL or namespace mismatch, and requires explicit approval. Namespace cascade deletion requires a second approval. Never auto-teardown unknown, mixed-owner, pre-existing, or Terraform-owned resources. Terraform mode uses only its configured backend and state.

### T5: Deterministic Browser Generator

FAIL in any required browser check blocks Phase 2 execution. Platform telemetry is evaluated only after the immediate receipt passes.

<!-- markdownlint-disable MD013 -->

1. **PF-T5-1: Runtime** — `node --version` reports Node.js 22 or newer.
2. **PF-T5-2: Scenario manifest** — `node scripts/csd-traffic.mjs --list` exits `0` and lists exactly these 11 stable scenarios: `login-credential-skimmer`, `registration-harvester`, `payment-overlay-card-skimmer`, `obfuscated-loader`, `multi-cdn-injection`, `tag-manager-hijack`, `multi-channel-exfiltration`, `high-volume-domain-exfiltration`, `form-overlay`, `keylogger-simulation`, and `maximum-detection`. No aliases are accepted.
3. **PF-T5-3: CLI selection** — execution has exactly one selector form: one or more repeatable `--scenario` values, or `--all`. There is no implicit selector. `--list`, `--print-script`, and `--help` are nonexecution modes. `--timeout` and `--settle` accept validated durations; settle time is browser-event collection, not a CSD timing promise.
4. **PF-T5-4: Loopback CDP** — a dedicated Chrome or Chromium profile exposes the configured loopback endpoint. Do not use a remote or credential-bearing CDP URL. The runner owns a new isolated context/page but does not close the external browser.
5. **PF-T5-5: Authorized target** — the target is the built-in exact HTTPS reference or an exact host repeated through `--allow-host`. HTTP, IP literals, wildcard/suffix authorization, credentials, non-default ports, unauthorized redirects, and a mismatched final document origin fail closed.
6. **PF-T5-6: Receipt destination and streams** — select a private ignored path such as `.artifacts/csd/<run>.json`, or use `--receipt -`. With `-`, stdout contains only JSON and human logs use stderr. Never commit receipts or CDP session data.
7. **PF-T5-7: Immediate receipt gate** — require schema/run/start/end/duration, tool name/runtime, requested scenarios, target origin/routes, exact allowlist, sanitized CDP endpoint, sanitized Log/console and Network evidence, per-scenario assertions/markers, protected-document and instrumentation evidence, aggregate success/caveats, and deterministic DOM/target/context/listener cleanup. `eventual_csd_evidence` remains null/separate.
8. **PF-T5-8: Scenario-specific evidence** — require native-setter synthetic markers for populated forms, masked-only payment-overlay evidence, encoded/decoded URL equality, exactly four multi-CDN attempts, run-scoped tag metadata, exactly three exfil channels, exactly five scripts plus two POSTs for `high-volume-domain-exfiltration`, overlay geometry/removal, aggregate periodic keylogger POST counts, and canonical primitive composition for `maximum-detection`.
9. **PF-T5-9: Failure receipt** — when a destination is requested, an atomic receipt is written even after execution or cleanup failure. Preserve the primary error in `error` and runner cleanup failures in `cleanup.errors`. Candidate failures and timed-out outcomes remain observed evidence and are never relabeled as loads.
10. **PF-T5-10: Claim boundary** — overlay and keylogger scenarios establish DOM behavior, original-field observation, and aggregate key-event counts only. They never establish captured values or guaranteed CSD classification. Do not claim every CDN candidate loaded or appeared.
11. **PF-T5-11: Manual fallback** — generate the payload only with canonical `node scripts/csd-traffic.mjs --print-script <scenario>`. Do not keep a duplicate payload in documentation or another script.
12. **PF-T5-12: Explicit post-receipt correlation** — the runner has no embedded/raw API client. Only after the immediate gate passes, use separate read-only `xcsh_api` operations scoped to the receipt window, protected origin, and exact reviewed Network hosts. Label results `OBSERVED`, `NOT_OBSERVED`, `PENDING`, or `ERROR`; never require fixed detection time or complete classification for generator success.
<!-- markdownlint-enable MD013 -->

### T6: End-to-End Proof Chain

All common checks and the checks for the selected cloud scenario must pass before presenting the environment. Ownership mode (`api|terraform`) does not select the cloud scenario.

**Common F5 path evidence:**

1. The non-empty DNS A-record set exactly equals the current VIP set from the exact LB in the expected namespace.
2. The ACME challenge CNAME or TXT owner and value match current certificate or DNS metadata; any non-empty record is not sufficient.
3. The exact protected-domain name and namespace are registered.
4. The F5 Distributed Cloud virtual host reports `VIRTUAL_HOST_READY`, and the automatic certificate reports a valid state.
5. HTTP redirects to HTTPS; HTTPS returns the expected scenario-specific application marker and contains an injected `__imp_apg__` script reference.
6. A recent F5 access-log event recorded after the validation request matches the exact protected host.
7. The deterministic generator receipt records the protected document, `__imp_apg__`, immediate operation outcomes, cleanup, and whether a browser `dip` request was observed.

**AWS reference evidence:** ECS reaches steady state, an ALB target is healthy, and recent CloudWatch application logs, VPC Flow Logs, and ALB access logs show delivery.

**Azure alternate evidence:** the exact subscription, resource group, resource IDs, deployment owner, and provisioning state are verified from the Azure source of truth, and a recent Azure application-log event is observed after the protected validation request. Do not apply AWS ECS, ALB, CloudWatch, flow-log, or S3 assertions to Azure.

When Terraform owns the selected stack, a final refresh-aware Terraform plan must report no drift. An API `200` or successful Terraform apply proves configuration acceptance, not this operational chain. Certificate/origin propagation and transient F5 `503` responses require bounded retry and fresh observation.

### Page Tamper Header Experiment Gates

These gates qualify a controlled candidate-header experiment; they do not establish an official monitored-header list.

**Evidence correction:** On 2026-09-23, `ClientSideDefenseHttpHeaderModified` named
`x-content-type-options`, `x-frame-options`, and `cache-control`, reported `modification=Added`, and
included the exact protected path `/`. This proves detection for that event only, not Compromised
behavior or complete header coverage. The 2026-09-24 six-header global-value campaign is **INVALID
TEST** for Compromised-trigger conclusions because it had no controlled baseline/comparison cohorts
and initially searched current alerts rather than alert history. Its later bounded negative search
does not prove unsupported coverage.

1. **PF-PT-1: Evidence Boundary** — PASS only when current official Page Tamper documentation, both alert names, the historical evidence boundary, and candidate status as unconfirmed coverage are recorded.
2. **PF-PT-2: Dedicated Baseline** — PASS only when the inert `/csd-page-tamper/payment` endpoint returns the canonical page and all 12 exact headers to workstation and worker fresh browsers, with five empty synthetic fields, CSD injection, `dip`, healthy ordinary application traffic, and no Terraform drift.
3. **PF-PT-3: Controlled Cohorts** — PASS only when control and tampered profiles alternate at the identical endpoint within one bounded window. Control retains all 12 headers; a tampered request sends only `X-CSD-Page-Tamper: <header-id>`, omits exactly that header, and retains the other 11. No load-balancer or origin-pool mutation is permitted.
4. **PF-PT-4: Exact Alert Correlation** — PASS only when current alerts and alert history are polled and a record matches the exact namespace, selected header, `/csd-page-tamper/payment`, and experiment window. Generic or temporally adjacent alerts cannot satisfy a case.
5. **PF-PT-5: Canary** — Run `X-Content-Type-Options` first. If it does not reach `COMPROMISED`, complete recovery, stop the suite, and diagnose. Do not claim success from `MODIFIED_ONLY` or `NO_ALERT_WITHIN_WINDOW`.
6. **PF-PT-6: Conservative Outcome** — Assign exactly one of `COMPROMISED`, `MODIFIED_ONLY`, `NO_ALERT_WITHIN_WINDOW`, or `INVALID_TEST`; any incomplete validity or safety gate forces `INVALID_TEST`.
7. **PF-PT-7: Recovery** — PASS only after 15 minutes of control-only traffic, all 12 headers re-proven from workstation and worker, CSD injection and `dip` observed, run-owned artifacts cleaned, endpoint and ordinary application healthy, load balancer ready, and final refresh-aware Terraform plan reporting no changes.

The dedicated mixed-cohort design remains a hypothesis until live evidence satisfies every gate. Resolve quota, namespace, state-lock, certificate, or origin issues without changing ownership.

**Live status (2026-09-25/26):** The dedicated endpoint is deployed and bootstrap-proven. Bootstrap
run `dd91ea9b-3da3-4fc8-b24b-c32cdba2e863` (`2026-09-25T21:40:23.373Z` through
`2026-09-25T22:42:18.638Z`) returned `alerts=[]` and passed endpoint/root health, 12 exact
headers, five empty fields, CSD script, both ALB target groups, load-balancer readiness, certificate
validity, and no-drift checks. The valid XCTO canary run
`69f30bd0-6dc2-4721-bb21-cae159032af2` (`2026-09-25T23:21:44.908Z` through
`2026-09-26T00:38:11.806Z`) completed 12/12 controls and 20/20 mixed pairs with valid telemetry
and `alerts=[]`; current alerts were zero and history was empty. Its classification is
`NO_ALERT_WITHIN_WINDOW`. Recovery passed with 10 control pairs, probes, readiness, cleanup, and
Terraform no drift. PF-PT-2, PF-PT-3, PF-PT-6, and PF-PT-7 are proven for this canary execution;
PF-PT-4 did not produce a correlation, and PF-PT-5 required the suite to stop. No remaining header
was run by design, and the Compromised hypothesis remains unvalidated.
