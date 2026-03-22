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

FAIL in any T0 check blocks all subsequent tiers.

1. **PF-T0-1: API Connectivity** — GET `/api/web/namespaces` with
   `--connect-timeout 10`. If `000` or timeout, try adding
   `--tlsv1.2 --tls-max 1.2` (some environments reject TLS 1.3).
   If still failing, report FAIL and stop.
2. **PF-T0-2: Namespace Access** — GET
   `/api/config/namespaces/{namespace}/http_loadbalancers`. If `403`
   or `404`, report FAIL and stop.
3. **PF-T0-3: CSD API Access** — GET
   `/api/shape/csd/namespaces/{namespace}/status`. If `403`, report
   FAIL and stop.

### T1: Quotas & Capacity

Mixed blocking — PF-T1-1 is WARN (healthchecks are optional for
CSD). PF-T1-4 through PF-T1-6 are FAIL if quota is exhausted
(origin pools, load balancers, and protected domains are required
for the demo to proceed).

4. **PF-T1-1: Healthcheck Quota** — POST a probe healthcheck named
   `preflight-quota-probe`, then DELETE it. If creation returns
   error code `8` (exhausted limits), record as WARN (not FAIL —
   healthchecks are optional for CSD).
5. **PF-T1-2: Origin Pool Count** — GET origin pools list, record
   count.
6. **PF-T1-3: HTTP LB Count** — GET LB list, record count.
7. **PF-T1-4: Origin Pool & Endpoint Quota** — POST a probe origin
   pool named `preflight-origin-probe` with one endpoint (RFC 5737
   TEST-NET IP `192.0.2.1`), then DELETE it. If creation returns
   error code `8` (exhausted limits for origin pools or endpoints),
   record as FAIL — origin pools are required for the demo. This
   single probe tests both origin pool and endpoint sub-object
   quota simultaneously.
8. **PF-T1-5: HTTP Load Balancer Quota** — POST a probe HTTP LB
   named `preflight-lb-probe` with `default_route_pools: []` and
   `dns_volterra_managed: false`, then DELETE it. If creation
   returns error code `8`, record as FAIL — load balancers are
   required. One probe covers both HTTP and HTTPS LBs (same API
   object kind `http_loadbalancers`).
9. **PF-T1-6: Protected Domain Quota** — POST a probe protected
   domain named `preflight-probe.example.com` with
   `protected_domain: "example.com"` (RFC 2606), then DELETE it.
   If creation returns error code `8`, record as FAIL. A `409`
   (domain already exists) counts as PASS — it proves the API
   accepts domain registrations and quota is not exhausted.

### T2: Platform Prerequisites

FAIL in any T2 check blocks execution.

10. **PF-T2-1: CSD Tenant Status** — GET CSD status, check
    `isConfigured` and `isEnabled`. If either is `false`, report
    FAIL and stop.
11. **PF-T2-2: DNS Zone Exists** — GET
    `/api/config/dns/namespaces/system/dns_zones/{root_domain}`.
    Record status code. `404` is WARN (external DNS may be in use).
    `403` is WARN (token may lack system namespace access).
12. **PF-T2-3: DNS Managed Records** — only if T2-2 returned `200`,
    check `allow_http_lb_managed_records`. If `true`, record PASS.
    If `false` or `null` and F5 XC is the authoritative DNS provider
    (PF-T2-4 shows `f5clouddns.com` nameservers), auto-enable using
    GET+PUT on the DNS zone, then re-check to confirm. If external
    DNS, record as INFO (managed records are not applicable). If
    auto-remediation fails (PUT returns error), record as FAIL.
13. **PF-T2-4: DNS Nameserver Authority** — run
    `dig +short NS {root_domain}`. Record whether F5 XC or external.

### T3: Origin Health

WARN only — does not block execution.

**Skip condition:** If `F5XC_ORIGIN_IP` falls within an RFC 5737
TEST-NET range (`192.0.2.0/24`, `198.51.100.0/24`, or
`203.0.113.0/24`), skip the entire T3 tier. Record both PF-T3-1 and
PF-T3-2 as **SKIP** with note: "Origin IP is an RFC 5737 TEST-NET
documentation address — not routable, connectivity testing skipped."
These ranges are reserved for use in documentation and examples per
[RFC 5737](https://datatracker.ietf.org/doc/html/rfc5737) and will
never respond to connectivity tests.

14. **PF-T3-1: Origin Connectivity** — cURL the origin IP:port with
    `--connect-timeout 10`. Record HTTP status. `000` is WARN.
15. **PF-T3-2: HTML Content** — only if T3-1 returned a valid HTTP
    status, check if response contains `</html>`. Record result.

### T4: Environment Clean

Executes auto-teardown if leftover objects are found.

16. Run the six pre-flight commands (HTTP LB, HTTPS LB, Origin Pool,
    Healthcheck, protected domains, mitigated domains). Record each
    HTTP status code.
17. Also check for stale probe objects from a prior interrupted
    pre-flight run — delete if found:
    - `preflight-quota-probe` (healthcheck)
    - `preflight-lb-probe` (HTTP load balancer)
    - `preflight-origin-probe` (origin pool)
    - `preflight-probe.example.com` (protected domain)
18. **Auto-teardown if needed** — if any objects exist (HTTP `200` on
    infrastructure checks, or non-zero real counts on
    protected/mitigated domains), run the full Phase 4 teardown by
    reading and executing commands from
    `docs/api-automation/phase-4-teardown.mdx`. No confirmation
    needed — Prepare is pre-meeting cleanup.
19. **Re-run pre-flight** — execute the same pre-flight checks to
    confirm all objects return `404` and counts are 0. If any object
    still exists, report failure and stop.

### T5: Certificate Readiness

INFO only.

20. **PF-T5-1: Recent Certificate Issuance History** — there is no
    API to query Let's Encrypt rate limits directly. Note as INFO
    that frequent create/destroy cycles can exhaust the weekly limit
    (5 duplicate certificates per week per domain). If this demo
    domain has been torn down and rebuilt multiple times recently,
    include a warning that HTTPS may be rate-limited.
21. **PF-T5-2: Cert State** — only if an HTTPS LB existed in T4
    (before teardown), note the `cert_state` value observed. If
    `AutoCertDomainRateLimited`, include a warning that HTTPS may
    not be available and the demo should plan for HTTP-only.
