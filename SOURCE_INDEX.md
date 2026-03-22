# CSD — Research Source Index

## Local Knowledge Base

| ID | File | Topics |
| -- | ---- | ------ |
| LOCAL-OVERVIEW | `docs/overview.mdx` | CSD overview, capabilities, architecture |
| LOCAL-INDEX | `docs/index.mdx` | Landing page, product summary |
| LOCAL-XC-CONFIG | `docs/xc-configuration.mdx` | F5 XC console configuration, LB setup |
| LOCAL-CSD-CONSOLE | `docs/csd-console.mdx` | CSD dashboard, detections UI |
| LOCAL-TELEMETRY | `docs/telemetry-beacons.mdx` | Telemetry scripts, beacon format |
| LOCAL-TRIGGER | `docs/trigger-detection.mdx` | Detection triggering, attack simulation |
| LOCAL-ATTACK | `docs/attack-scripts.mdx` | Attack scripts, skimmer behavior |
| LOCAL-DEMO-SITE | `docs/demo-website.mdx` | Demo site setup, Juice Shop |
| LOCAL-DIAGNOSTICS | `docs/diagnostics.mdx` | Troubleshooting, diagnostic tests |
| LOCAL-REFERENCES | `docs/references.mdx` | External links, further reading |
| LOCAL-API-REF | `docs/api-reference.mdx` | CSD API endpoints, request/response |
| LOCAL-API-AUTO | `docs/api-automation/index.mdx` | API automation overview, variable resolution |
| LOCAL-PHASE1 | `docs/api-automation/phase-1-build.mdx` | Phase 1 build, provisioning |
| LOCAL-PHASE2 | `docs/api-automation/phase-2-attack.mdx` | Phase 2 attack simulation |
| LOCAL-PHASE3 | `docs/api-automation/phase-3-mitigate.mdx` | Phase 3 mitigation, allow/mitigate |
| LOCAL-PHASE4 | `docs/api-automation/phase-4-teardown.mdx` | Phase 4 teardown, cleanup |
| LOCAL-FAQ | `docs/faq.mdx` | Frequently asked questions — alerts, logging, SIEM, mitigation behavior, detection timing |

## F5 API Documentation

| ID | URL | Topics |
| -- | --- | ------ |
| F5-API-CSD | <https://docs.cloud.f5.com/docs-v2/api/shape-client-side-defense> | CSD API spec, enable/status/scripts/detections |
| F5-API-ALLOWED | <https://docs.cloud.f5.com/docs-v2/api/shape-client-side-defense-allowed-domain> | Allowed domain API |
| F5-API-PROTECTED | <https://docs.cloud.f5.com/docs-v2/api/shape-client-side-defense-protected-domain> | Protected domain API |
| F5-API-MITIGATED | <https://docs.cloud.f5.com/docs-v2/api/shape-client-side-defense-mitigated-domain> | Mitigated domain API |
| F5-API-SUB | <https://docs.cloud.f5.com/docs-v2/api/shape-client-side-defense-subscription> | CSD subscription API |
| F5-API-HEALTH | <https://docs.cloud.f5.com/docs-v2/api/healthcheck> | Healthcheck API |
| F5-API-LB | <https://docs.cloud.f5.com/docs-v2/api/views-http-loadbalancer> | HTTP load balancer API |

## F5 Product Documentation

| ID | URL | Topics |
| -- | --- | ------ |
| F5-CSD-ABOUT | <https://docs.cloud.f5.com/docs-v2/client-side-defense/concepts/about-csd> | CSD concepts, architecture, how it works |
| F5-CSD-HOWTO | <https://docs.cloud.f5.com/docs-v2/client-side-defense/how-tos/configure-csd> | CSD configuration guide |
| F5-CSD-FAQ | <https://docs.cloud.f5.com/docs-v2/client-side-defense/faqs/csd> | CSD frequently asked questions |

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

## Threat Research & Standards

| ID | URL | Topics |
| -- | --- | ------ |
| OWASP-CLICKJACKING | <https://owasp.org/www-community/attacks/Clickjacking> | Clickjacking, UI redressing, iframe overlay |
| OWASP-CLICKJACKING-DEFENSE | <https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html> | Clickjacking prevention, CSP frame-ancestors |
| OWASP-MITB | <https://owasp.org/www-community/attacks/Man-in-the-browser_attack> | Man-in-the-Browser, browser trojan, session hijack |
| OWASP-XSS | <https://owasp.org/www-community/attacks/xss/> | Cross-site scripting, script injection, DOM XSS |
| OWASP-CLIENT-SIDE-TOP10 | <https://owasp.org/www-project-top-10-client-side-security-risks/> | Client-side security risks ranking |
| MITRE-SUPPLY-CHAIN | <https://attack.mitre.org/techniques/T1195/> | Supply chain compromise T1195 |
| MITRE-SUPPLY-CHAIN-SW | <https://attack.mitre.org/techniques/T1195/002/> | Software supply chain compromise T1195.002 |
| MITRE-MITB | <https://attack.mitre.org/techniques/T1185/> | Man-in-the-Browser T1185 |
| MITRE-EXFILTRATION | <https://attack.mitre.org/tactics/TA0010/> | Data exfiltration tactic TA0010 |
| MITRE-RESOURCE-HIJACK | <https://attack.mitre.org/techniques/T1496/> | Resource hijacking T1496, cryptojacking |
| AKAMAI-WEB-SKIMMING | <https://www.akamai.com/glossary/what-is-web-skimming> | Web skimming, digital skimming definition |
| SANSEC-MAGECART | <https://sansec.io/what-is-magecart> | Magecart, formjacking, e-commerce skimming |
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
| "How do I configure X?" | LOCAL-XC-CONFIG | F5-CSD-HOWTO |
| "What does the dashboard show?" | LOCAL-CSD-CONSOLE | F5-CSD-ABOUT |
| "How does telemetry work?" | LOCAL-TELEMETRY | F5-CSD-ABOUT |
| "What is clickjacking?" | OWASP-CLICKJACKING | LOCAL-OVERVIEW |
| "What is man-in-the-browser?" | OWASP-MITB, MITRE-MITB | LOCAL-OVERVIEW |
| "What is a supply chain attack?" | MITRE-SUPPLY-CHAIN | F5-ATTACK-VECTORS |
| "What is cryptojacking?" | MITRE-RESOURCE-HIJACK | LOCAL-OVERVIEW |
| "What is web skimming/Magecart?" | SANSEC-MAGECART, AKAMAI-WEB-SKIMMING | F5-ATTACK-VECTORS |
| "What data does CSD collect?" | F5-CSD-PRIVACY | LOCAL-TELEMETRY |
