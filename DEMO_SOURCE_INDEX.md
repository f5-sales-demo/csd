# CSD — Research Source Index

## Local Knowledge Base

| ID | File | Topics |
| -- | ---- | ------ |
| LOCAL-OVERVIEW | `docs/en/overview.mdx` | CSD overview, one-LB architecture, ownership modes |
| LOCAL-INDEX | `docs/en/index.mdx` | Landing page, product summary |
| LOCAL-XC-CONFIG | `docs/en/xc-configuration.mdx` | F5 XC configuration and all-pages injection |
| LOCAL-CSD-CONSOLE | `docs/en/csd-console.mdx` | CSD dashboard and detections UI |
| LOCAL-TELEMETRY | `docs/en/telemetry-beacons.mdx` | Injected script and `dip` beacon observations |
| LOCAL-TRIGGER | `docs/en/trigger-detection.mdx` | Authorized detection simulation |
| LOCAL-ATTACK | `docs/en/attack-scripts.mdx` | Attack scripts and skimmer behavior |
| LOCAL-DEMO-SITE | `docs/en/demo-website.mdx` | AWS Juice Shop reference and Azure alternate |
| LOCAL-DIAGNOSTICS | `docs/en/diagnostics.mdx` | Provider-specific origin and end-to-end checks |
| LOCAL-REFERENCES | `docs/en/references.mdx` | External links and further reading |
| LOCAL-API-REF | `docs/en/api-reference.mdx` | Current CSD endpoint paths and payloads |
| LOCAL-API-AUTO | `docs/en/demo/index.mdx` | API/Terraform ownership selection and readiness |
| LOCAL-PHASE1 | `docs/en/demo/phase-1-build.mdx` | API-owned build and verification |
| LOCAL-PHASE2 | `docs/en/demo/phase-2-attack.mdx` | Ownership-neutral attack simulation |
| LOCAL-PHASE3 | `docs/en/demo/phase-3-mitigate.mdx` | API-owned or Terraform-owned mitigation paths |
| LOCAL-PHASE4 | `docs/en/demo/phase-4-teardown.mdx` | Owner-specific cleanup |
| LOCAL-AZURE | `docs/en/demo/third-party-lifecycle.mdx` | Separate Azure full-origin alternate |
| LOCAL-TERRAFORM | `docs/en/terraform/index.mdx` | AWS reference Terraform workflow |
| LOCAL-FAQ | `docs/en/faq.mdx` | Alerts, logging, SIEM, mitigation, detection timing |
| LOCAL-PRODUCT-EXPERTISE | `DEMO_PRODUCT_EXPERTISE.md` | Product boundaries, telemetry, threat coverage, and Magecart kill chain |

## F5 API Documentation

| ID | URL | Topics |
| -- | --- | ------ |
| F5-API-ENRICHED | <https://f5-sales-demo.github.io/api-specs-enriched/en/> | Canonical F5 Distributed Cloud API documentation |
| F5-API-CSD | <https://f5-sales-demo.github.io/api-specs-enriched/en/api-reference/shape-api/> | Shape CSD status, domains, scripts, form fields, and mitigation operations |
| F5-API-LB | <https://f5-sales-demo.github.io/api-specs-enriched/en/api-reference/virtual-api/> | HTTP load balancer schema and operations |
| F5-API-ORIGIN | <https://f5-sales-demo.github.io/api-specs-enriched/en/api-reference/virtual-api/> | Origin pool schema and `public_name`/`public_ip` oneOf choices |
| F5-API-HEALTH | <https://f5-sales-demo.github.io/api-specs-enriched/en/api-reference/virtual-api/> | Optional healthcheck schema |
| F5-QUOTA-REF | <https://docs.cloud.f5.com/docs-v2/platform/reference/default-quota-reference> | Default quota values by plan tier |

## Infrastructure Source Provenance

| ID | Source | Provenance |
| -- | ------ | ---------- |
| TF-AWS | `terraform/aws/versions.tf`, `terraform/aws/variables.tf`, `terraform/aws/main.tf`, `terraform/aws/outputs.tf`, `terraform/aws/tests/stack.tftest.hcl` | Canonical AWS reference implementation using `f5-sales-demo/xcsh` |
| ORIGIN-VENDORED | `terraform/aws/vendor/aws-juice-shop/` | Vendored from `f5-sales-demo/origin-server` commit `d6384bb0621c4c1eceb38d55a6b63e7b9cc7083a` |
| ORIGIN-PUBLISHED | <https://f5-sales-demo.github.io/origin-server/> | Published origin documentation released by merge `595841996ef7e782870be8200dce4775defb7e80` |

The AWS Terraform stack and standalone API workflow create the same logical F5 Distributed Cloud architecture but are mutually exclusive owners. Choose one ownership mode. Never run the API create/update/delete workflow against resources present in Terraform state.

## F5 Product Documentation

| ID | URL | Topics |
| -- | --- | ------ |
| F5-CSD-ABOUT | <https://docs.cloud.f5.com/docs-v2/client-side-defense/concepts/about-csd> | CSD concepts, architecture, how it works |
| F5-CSD-HOWTO | <https://docs.cloud.f5.com/docs-v2/client-side-defense/how-tos/configure-csd> | CSD configuration guide |

## Community & Technical Articles

| ID | URL | Topics |
| -- | --- | ------ |
| F5-COMMUNITY-AUTOMATION | <https://community.f5.com/kb/TechnicalArticles/automation-of-f5-distributed-cloud-platform-client-side-defense-feature---part-i/305052> | CSD API automation, scripting |
| F5-ATTACK-VECTORS | <https://community.f5.com/kb/technicalarticles/javascript-supply-chains-magecart-and-f5-xc-client-side-defense-demo/296612> | Magecart, supply chain attacks, skimming |

## Marketing & Product Pages

| ID | URL | Topics |
| -- | --- | ------ |
| F5-PRODUCT-PAGE | <https://www.f5.com/products/distributed-cloud-services/client-side-defense#capabilities> | CSD capabilities, features, positioning |
| F5-DEMO-PAGE | <https://www.f5.com/resources/demos/introduction-to-f5-distributed-cloud-client-side-defense> | CSD demo overview, introduction |
| F5-SOLUTION-BRIEF | <https://cdn.studio.f5.com/files/k6fem79d/production/fa6729948127c9d6c7a02c28e091350c0b6e8b22.pdf> | CSD solution brief |
| F5-MARKETING-PDF | <https://cdn.studio.f5.com/files/k6fem79d/production/6cf856310ae57017926c3ba475c6199c9747d92b.pdf> | CSD marketing material |

## Video Content

| ID | URL | Topics |
| -- | --- | ------ |
| F5-YOUTUBE-DEMO | <https://www.youtube.com/watch?v=esQtt2Ek3Ug> | CSD demo video |
| F5-VIMEO-MARKETING | <https://vimeo.com/810975557/cd8d96ecca> | CSD marketing video |

## Compliance & Standards

| ID | URL | Topics |
| -- | --- | ------ |
| PCI-BLOG | <https://www.f5.com/company/blog/pci-dss-v4-0-browser-based-attacks> | PCI DSS v4.0, browser attacks, 6.4.3, 11.6.1 |
| F5-PCI-BLOG | <https://www.f5.com/company/blog/distributed-cloud-client-side-defense-prepares-customers-for-pci-dss> | PCI DSS v4.0.1 CSD compliance mapping |
| PCI-SSC-LIBRARY | <https://www.pcisecuritystandards.org/document_library/> | PCI DSS v4.0 standard documents |
| PCI-DSS-V4-STANDARD | <https://www.pcisecuritystandards.org/document_library/?document=pci_dss> | PCI DSS v4.0.1 full standard — Section 6.4.3 (script inventory), Section 11.6.1 (tamper detection) |

## Threat Research & Standards

| ID | URL | Topics |
| -- | --- | ------ |
| OWASP-CLICKJACKING | <https://community.owasp.org/attacks/Clickjacking> | Clickjacking, UI redressing, iframe overlay |
| OWASP-CLICKJACKING-DEFENSE | <https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html> | Clickjacking prevention, CSP frame-ancestors |
| OWASP-XSS | <https://community.owasp.org/attacks/xss/> | Cross-site scripting, script injection, DOM XSS |
| OWASP-CLIENT-SIDE-TOP10 | <https://owasp.org/projects/top-10-client-side-security-risks> | Candidate client-side security risks |
| MITRE-SUPPLY-CHAIN | <https://attack.mitre.org/techniques/T1195/> | Supply Chain Compromise T1195 |
| MITRE-SUPPLY-CHAIN-SW | <https://attack.mitre.org/techniques/T1195/002/> | Compromise Software Supply Chain T1195.002 |
| MITRE-BROWSER-SESSION-HIJACKING | <https://attack.mitre.org/techniques/T1185/> | Browser Session Hijacking T1185 |
| MITRE-EXFILTRATION | <https://attack.mitre.org/tactics/TA0010/> | Exfiltration tactic TA0010 |
| MITRE-RESOURCE-HIJACK | <https://attack.mitre.org/techniques/T1496/> | Resource Hijacking T1496, including cryptomining |
| AKAMAI-WEB-SKIMMING | <https://www.akamai.com/glossary/what-is-web-skimming> | Web skimming, digital skimming definition |
| SANSEC-MAGECART | <https://sansec.io/what-is-magecart> | Magecart, formjacking, e-commerce skimming, group taxonomy, notable breaches (BA, Ticketmaster, NewEgg) |
| ANGULAR-ZONE-JS | <https://angular.dev/guide/zone> | Angular zone.js API patching, browser API interception, implications for browser automation |
| F5-CSD-PRIVACY | <https://www.f5.com/company/policies/f5-distributed-cloud-client-side-defense-privacy-statement> | CSD data collection, privacy, what telemetry contains |

## Question Routing Guide

| Question pattern | Try first | Then try |
| ---------------- | --------- | -------- |
| "How does X work?" | LOCAL docs | F5-CSD-ABOUT |
| "What API endpoint for X?" | LOCAL-API-REF | F5-API-CSD, F5-API-* |
| "Is CSD PCI compliant?" | LOCAL-OVERVIEW | PCI-BLOG |
| "How does CSD compare to X?" | F5-PRODUCT-PAGE | F5-SOLUTION-BRIEF |
| "Can CSD detect X?" | LOCAL-OVERVIEW (boundaries) | F5-CSD-ABOUT |
| "How do I automate X?" | LOCAL-API-AUTO | F5-COMMUNITY-AUTOMATION |
| "What is Magecart?" | F5-ATTACK-VECTORS | WebSearch fallback |
| "Walk me through a Magecart attack" | LOCAL-PRODUCT-EXPERTISE (Magecart Kill Chain) | SANSEC-MAGECART |
| "How do I configure X?" | LOCAL-XC-CONFIG | F5-CSD-HOWTO |
| "What does the dashboard show?" | LOCAL-CSD-CONSOLE | F5-CSD-ABOUT |
| "How does telemetry work?" | LOCAL-TELEMETRY | F5-CSD-ABOUT |
| "What is clickjacking?" | OWASP-CLICKJACKING | LOCAL-OVERVIEW |
| "What is browser session hijacking?" | MITRE-BROWSER-SESSION-HIJACKING | LOCAL-OVERVIEW |
| "What is a supply chain attack?" | MITRE-SUPPLY-CHAIN | F5-ATTACK-VECTORS |
| "What is cryptojacking?" | MITRE-RESOURCE-HIJACK | LOCAL-OVERVIEW |
| "What is web skimming/Magecart?" | SANSEC-MAGECART, AKAMAI-WEB-SKIMMING | F5-ATTACK-VECTORS |
| "What data does CSD collect?" | F5-CSD-PRIVACY | LOCAL-TELEMETRY |
