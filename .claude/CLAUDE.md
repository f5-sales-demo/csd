# Persona Activation

This repository uses Sales Engineer persona skills from the
`f5xc-sales-engineer` plugin. When the user's message matches
a trigger pattern below, invoke the corresponding skill.

## Trigger Map

| Trigger phrases | Skill | Action |
| --------------- | ----- | ------ |
| "prepare the demo", "prep the demo", "get ready for the demo", "is the demo environment ready", "is the demo ready", "the meeting will be starting soon", "check the demo", "pre-flight", "preflight check" | `f5xc-sales-engineer:demo-executor` | Invoke skill, run Prepare stage |
| "run the demo", "execute the demo", "start the demo", "API demo" | `f5xc-sales-engineer:demo-executor` | Invoke skill, run Execute stage |
| "question and answer", "Q&A", "open it up for questions", "take questions" | `f5xc-sales-engineer:demo-executor` | Invoke skill, enter Q&A stage |
| "tear down", "clean up", "tear down the demo", "end the meeting" | `f5xc-sales-engineer:demo-executor` | Invoke skill, run Teardown stage |
| "walk through the demo", "present the demo", "show the demo", "walkthrough" | `f5xc-sales-engineer:presenter` | Invoke skill, begin walkthrough |
| "answer questions", "CSD question", "what does CSD", "explain CSD" | `f5xc-sales-engineer:subject-matter-expert` | Invoke skill, answer as SME |

## Convention Files

Skills read product-specific content from these repo-local files:

| File | Purpose | Required |
| ---- | ------- | -------- |
| `PRODUCT_EXPERTISE.md` | Product capabilities, detection signals, threat coverage, API reference | Yes |
| `WALKTHROUGH_CONFIG.md` | Demo app URL, walkthrough order, timing | For presenter |
| `SOURCE_INDEX.md` | Research source catalog for demo-researcher agent | For Q&A |
| `READINESS_MATRIX.md` | Pre-flight checks, required/optional variables | For prepare/teardown |
| `docs/api-automation/` | Phase files with cURL commands | For demo-executor |

## Ambiguous Intent

If the user's request relates to demos but doesn't clearly match
a trigger, read `PRODUCT_EXPERTISE.md` first to determine context,
then activate the most appropriate skill.
