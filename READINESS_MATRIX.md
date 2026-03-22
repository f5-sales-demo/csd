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

WARN only — does not block execution.

4. **PF-T1-1: Healthcheck Quota** — POST a probe healthcheck named
   `preflight-quota-probe`, then DELETE it. If creation returns
   error code `8` (exhausted limits), record as WARN (not FAIL —
   healthchecks are optional for CSD).
5. **PF-T1-2: Origin Pool Count** — GET origin pools list, record
   count.
6. **PF-T1-3: HTTP LB Count** — GET LB list, record count.

### T2: Platform Prerequisites

FAIL in any T2 check blocks execution.

7. **PF-T2-1: CSD Tenant Status** — GET CSD status, check
   `isConfigured` and `isEnabled`. If either is `false`, report
   FAIL and stop.
8. **PF-T2-2: DNS Zone Exists** — GET
   `/api/config/dns/namespaces/system/dns_zones/{root_domain}`.
   Record status code. `404` is WARN (external DNS may be in use).
   `403` is WARN (token may lack system namespace access).
9. **PF-T2-3: DNS Managed Records** — only if T2-2 returned `200`,
   check `allow_http_lb_managed_records`. Record `true`/`false`.
10. **PF-T2-4: DNS Nameserver Authority** — run
    `dig +short NS {root_domain}`. Record whether F5 XC or external.

### T3: Origin Health

WARN only — does not block execution.

11. **PF-T3-1: Origin Connectivity** — cURL the origin IP:port with
    `--connect-timeout 10`. Record HTTP status. `000` is WARN.
12. **PF-T3-2: HTML Content** — only if T3-1 returned a valid HTTP
    status, check if response contains `</html>`. Record result.

### T4: Environment Clean

Executes auto-teardown if leftover objects are found.

13. Run the six pre-flight commands (HTTP LB, HTTPS LB, Origin Pool,
    Healthcheck, protected domains, mitigated domains). Record each
    HTTP status code.
14. Also check for stale `preflight-quota-probe` healthcheck from a
    prior interrupted run — delete if found.
15. **Auto-teardown if needed** — if any objects exist (HTTP `200` on
    infrastructure checks, or non-zero real counts on
    protected/mitigated domains), run the full Phase 4 teardown by
    reading and executing commands from
    `docs/api-automation/phase-4-teardown.mdx`. No confirmation
    needed — Prepare is pre-meeting cleanup.
16. **Re-run pre-flight** — execute the same pre-flight checks to
    confirm all objects return `404` and counts are 0. If any object
    still exists, report failure and stop.

### T5: Certificate Readiness

INFO only.

17. **PF-T5-1: Recent Certificate Issuance History** — there is no
    API to query Let's Encrypt rate limits directly. Note as INFO
    that frequent create/destroy cycles can exhaust the weekly limit
    (5 duplicate certificates per week per domain). If this demo
    domain has been torn down and rebuilt multiple times recently,
    include a warning that HTTPS may be rate-limited.
18. **PF-T5-2: Cert State** — only if an HTTPS LB existed in T4
    (before teardown), note the `cert_state` value observed. If
    `AutoCertDomainRateLimited`, include a warning that HTTPS may
    not be available and the demo should plan for HTTP-only.
