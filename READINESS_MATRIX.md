# CSD — Readiness Verification Matrix

## Required Variables

| Variable | Required | Default | Placeholder (treat as missing) |
| --- | --- | --- | --- |
| `F5XC_API_TOKEN` | **Yes** | — | `example-api-token` |
| `F5XC_API_URL` | **Yes** | — | `https://example-tenant.console.ves.volterra.io` |
| `F5XC_NAMESPACE` | **Yes** | — | `example-namespace` |
| `F5XC_DOMAINNAME` | **Yes** | — | `app.example.com` |
| `F5XC_ROOT_DOMAIN` | **Yes** | — | `example.com` |
| `F5XC_LB_NAME` | **Yes** | — | `example-lb-name`, `example-lb` |
| `F5XC_EMAIL` | **Yes** | — | `user@example.com` |

## Optional Variables

| Variable | Default |
| --- | --- |
| `F5XC_HC_NAME` | `csd-hc` |
| `F5XC_ORIGIN_IP` | `44.232.69.192` |
| `F5XC_ORIGIN_POOL` | `csd-origin` |
| `F5XC_ORIGIN_PORT` | `3000` |

## Readiness Checks

### T0: Connectivity & Auth

FAIL in any T0 check blocks all subsequent tiers. Each check captures
the HTTP status code and pipes it through a jq filter that computes a
deterministic `{check, http_code, status, detail}` object — no
operator interpretation required.

1. **PF-T0-1: API Connectivity** — GET `/api/web/namespaces` with
   `--connect-timeout 10 --max-time 15`. jq computes: `200` → PASS,
   `401` → FAIL (token invalid), `0` → FAIL (network unreachable —
   try `--tlsv1.2 --tls-max 1.2`), all others → FAIL.
2. **PF-T0-2: Namespace Access** — GET
   `/api/config/namespaces/{namespace}/http_loadbalancers`. jq
   computes: `200` → PASS, `403` → FAIL (missing role binding),
   `404` → FAIL (namespace does not exist), all others → FAIL.
3. **PF-T0-3: CSD API Access** — GET
   `/api/shape/csd/namespaces/{namespace}/status`. jq computes:
   `200` → PASS, `403` → FAIL (missing CSD role binding), all
   others → FAIL.

### T1: Quotas & Capacity

Uses the Quota Usage API to query tenant-wide limits and current
usage for each object kind the demo needs. Calculates remaining
capacity and reports PASS/WARN/FAIL based on whether enough room
exists. Falls back to probe-and-delete if the Quota Usage API is
not accessible.

4. **PF-T1-0: Quota Usage Gate** — GET
   `/api/web/namespaces/system/quota/usage?namespace=system`. This
   endpoint requires the `system` namespace (not the demo
   namespace). If `200`, pass the `objects` map through a jq filter
   that computes a deterministic `gate` verdict (PASS/WARN/FAIL)
   by comparing each object kind's `remaining` capacity against the
   demo's `needed` count. If `403` or any error, fall back to
   probe-based checks (see Fallback below).

   The gate evaluates four object kinds:

   | Kind | Needed | Required | Min to proceed |
   | --- | --- | --- | --- |
   | `healthcheck` | 1 | No | 0 |
   | `origin_pool` | 1 | Yes | 1 |
   | `endpoint` | 1 | Yes | 1 |
   | `http_loadbalancer` | 2 (or 1 if HTTPS LB skeleton exists) | Yes | 1 |

   For each kind, the jq filter calculates:
   - `remaining = limit - usage` (unlimited if limit is `-1`)
   - `status = PASS` if `remaining >= needed`
   - `status = WARN` if `remaining >= min_proceed` but `< needed`
   - `status = FAIL` if `remaining < min_proceed` and kind is
     required (WARN if optional)

   The overall `gate` is FAIL if any check is FAIL, WARN if any is
   WARN, PASS otherwise. A FAIL gate blocks demo execution.

5. **PF-T1-4: Protected Domain Quota** — CSD protected domains do
   not appear in the platform Quota Usage API. Use probe-based
   check: POST a probe protected domain named
   `preflight-probe.example.com` with
   `protected_domain: "example.com"` (RFC 2606), then DELETE it.
   If creation returns error code `8`, record as FAIL. A `409`
   (domain already exists) counts as PASS.

### Fallback: Probe-Based Quota Checks

If PF-T1-0 fails (403, 404, or unexpected format), fall back to
probe-and-delete for all object kinds. Create and immediately
delete temporary objects to test whether the tenant has capacity:

- `preflight-quota-probe` healthcheck
- `preflight-origin-probe` origin pool (tests both origin pool and
  endpoint sub-object quota simultaneously)
- `preflight-lb-probe` HTTP load balancer
- `preflight-probe.example.com` protected domain

Error code `8` from creation indicates exhausted limits. Record as
WARN for healthchecks (optional) or FAIL for required objects.

### T2: Platform Prerequisites

FAIL in any T2 check blocks execution. Each check computes a
deterministic `{check, status, detail}` object via jq.

10. **PF-T2-1: CSD Tenant Status** — GET CSD status. jq computes:
    `{check, configured, enabled, status, detail}` where `status` is
    PASS if both `.isConfigured` and `.isEnabled` are `true`, FAIL
    otherwise.
11. **PF-T2-2: DNS Zone Exists** — GET
    `/api/config/dns/namespaces/system/dns_zones/{root_domain}`.
    HTTP code captured in variable, jq computes: `200` → PASS,
    `404` → WARN (external DNS may be in use), `403` → WARN (token
    may lack system namespace access), all others → FAIL.
12. **PF-T2-3: DNS Managed Records** — only if T2-2 returned `200`.
    jq computes: `{check, managed_records, status, detail}` where
    `status` is PASS if `allow_http_lb_managed_records` is `true`,
    WARN otherwise. If WARN and PF-T2-4 shows F5 XC nameservers,
    auto-enable using GET+PUT, then re-check. If external DNS,
    record as INFO. If auto-remediation fails, record as FAIL.
13. **PF-T2-4: DNS Nameserver Authority** — `dig +short NS`
    output piped through `jq -Rs` which computes:
    `{check, nameservers, status, detail}` where `status` is PASS
    if output contains `f5clouddns.com`, INFO for external DNS,
    FAIL if no NS records found.

### T3: Origin Health

WARN only — does not block execution.

**Skip condition:** A computed check (`PF-T3-skip`) pipes
`F5XC_ORIGIN_IP` through `jq -Rs` to test against RFC 5737 TEST-NET
ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`). jq
outputs `{check, origin_ip, is_test_net, status, detail}` where
`status` is SKIP if the IP matches a TEST-NET range, CONTINUE
otherwise. If SKIP, record PF-T3-1 and PF-T3-2 as SKIP and proceed
to T4. These ranges are reserved for documentation per
[RFC 5737](https://datatracker.ietf.org/doc/html/rfc5737) and will
never respond to connectivity tests.

14. **PF-T3-1: Origin Connectivity** — cURL the origin IP:port with
    `--connect-timeout 10 --max-time 15`. HTTP code captured in
    variable, jq computes: `200–599` → PASS, `0` → WARN (origin
    unreachable from this network), all others → WARN.
15. **PF-T3-2: HTML Content** — only if T3-1 returned a valid HTTP
    status, check if response contains `</html>`. Outputs PASS or
    WARN deterministically.

### T4: Environment Clean

Executes auto-teardown if leftover objects are found. The pre-flight
check computes a deterministic `{objects, any_infra_exists,
any_csd_exists, status, action}` object via jq. The `status` field
is one of: CLEAN, HTTPS_SKELETON, ALL_EXIST, TEARDOWN_NEEDED, or
MITIGATIONS_ONLY.

- `CLEAN` — all objects return 404, all counts are 0.
- `HTTPS_SKELETON` — only the HTTPS LB exists and it is in skeleton
  state (empty `default_route_pools`, no `client_side_defense`). All
  other infra objects (HTTP LB, origin pool, healthcheck) return 404,
  and CSD objects (protected domains, mitigated domains) have count 0.
  This is a **clean-equivalent** state — the skeleton preserves the
  Let's Encrypt certificate from a prior teardown. See
  [Phase 4 — Teardown](/csd/api-automation/phase-4-teardown/) for why
  the HTTPS LB is preserved.
- `ALL_EXIST` — both HTTP LB and origin pool exist.
- `TEARDOWN_NEEDED` — partial infra exists (not a skeleton).
- `MITIGATIONS_ONLY` — only mitigated domains remain.

16. Run the six pre-flight commands (HTTP LB, HTTPS LB, Origin Pool,
    Healthcheck, protected domains, mitigated domains). Capture each
    HTTP status code and domain count, then pipe all six through jq
    to compute environment status deterministically. When the HTTPS LB
    returns `200`, also fetch the full object body to determine if it
    is a **skeleton** (empty `default_route_pools` and no
    `client_side_defense`) or a fully-configured LB. This distinction
    determines whether the status is `HTTPS_SKELETON`
    (clean-equivalent) or `TEARDOWN_NEEDED`.
17. Also check for stale probe objects from a prior interrupted
    pre-flight run — delete if found. These probes are only created
    when the Quota Usage API was unavailable and fallback
    probe-based checks were used, or for the protected domain
    probe (PF-T1-4) which always uses probe-based checking:
    - `preflight-quota-probe` (healthcheck)
    - `preflight-lb-probe` (HTTP load balancer)
    - `preflight-origin-probe` (origin pool)
    - `preflight-probe.example.com` (protected domain)
18. **Auto-teardown if needed** — if `status` is not CLEAN and not
    `HTTPS_SKELETON` (any non-skeleton objects exist), run the full
    Phase 4 teardown by reading and executing commands from
    `docs/api-automation/phase-4-teardown.mdx`. No confirmation
    needed — Prepare is pre-meeting cleanup. If `status` is
    `HTTPS_SKELETON`, no teardown is needed — the skeleton is
    preserved by design and Phase 1 will restore it via PUT.
19. **Re-run pre-flight** — execute the same pre-flight checks to
    confirm `status` is CLEAN or `HTTPS_SKELETON`. For CLEAN: `404`
    on all objects, counts are 0. For `HTTPS_SKELETON`: HTTPS LB
    returns `200` with skeleton state, all other objects return `404`,
    counts are 0. If any unexpected object still exists, report
    failure and stop.

### T5: Certificate Readiness

INFO only. Checks compute deterministic `{check, status, detail}`
objects.

20. **PF-T5-1: Recent Certificate Issuance History** — there is no
    API to query Let's Encrypt rate limits directly. Note as INFO
    that frequent create/destroy cycles can exhaust the weekly limit
    (5 duplicate certificates per exact identifier set per 7 days).
    The default teardown behavior preserves the HTTPS LB as a skeleton
    to avoid triggering new certificate requests. If the HTTPS LB was
    fully deleted and rebuilt multiple times recently, include a
    warning that HTTPS may be rate-limited.
21. **PF-T5-2: Cert State** — captures HTTP code and response body.
    jq computes `{check, cert_state, status, detail}`:
    - HTTP `404` → SKIP (no HTTPS LB exists)
    - `CertificateValid` → PASS
    - `AutoCertDomainRateLimited` → INFO (plan for HTTP-only)
    - `Pending`/`Started` → INFO (provisioning in progress)
    - All others → INFO with raw `cert_state` value

    When the HTTPS LB exists as a skeleton from a prior teardown,
    PF-T5-2 should still run and report the certificate state. A
    `CertificateValid` result confirms the skeleton preservation
    strategy is working — HTTPS will be available immediately after
    Phase 1 restores the LB via PUT, with no Let's Encrypt
    provisioning delay.
