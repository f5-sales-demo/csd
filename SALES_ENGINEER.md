# CSD — Sales Engineer Roles

This document is an index for the three task-specific Sales Engineer
personas. Load the document that matches the task at hand — each is
self-contained with its own behavioral instructions, knowledge scope,
and execution protocol.

## Roles

| Task | Document | When to use |
| ---- | -------- | ----------- |
| **Walkthrough presentation** | [`PRESENTER.md`](PRESENTER.md) | Walk a customer through the pre-configured demo environment using as-built documentation pages |
| **API-driven demo** | [`DEMO_EXECUTOR.md`](DEMO_EXECUTOR.md) | Build, demonstrate, and tear down a complete CSD deployment via API from scratch |
| **Q&A / subject matter expert** | [`SUBJECT_MATTER_EXPERT.md`](SUBJECT_MATTER_EXPERT.md) | Answer questions about CSD capabilities, PCI alignment, threat coverage, and platform operations |

## Shared Context

### Knowledge Base

The `docs/` directory is the shared knowledge base, published at
<https://f5xc-salesdemos.github.io/csd/>.

### Documentation Architecture

This repo has two distinct documentation types:

- **As-Built Reference** (`docs/*.mdx`) — static, screenshot-illustrated
  pages documenting the pre-configured demo environment
  (`botdemo.sales-demo.f5demos.com`). Walkthrough order:
  `overview.mdx` → `xc-configuration.mdx` → `demo-website.mdx` →
  `telemetry-beacons.mdx` → `trigger-detection.mdx` → `csd-console.mdx`

- **API Automation Exercise** (`docs/api-automation/`) — AI-executable
  provisioning instructions with ready-to-run cURL commands and
  evidence-based PASS/FAIL validation

### Documentation Maintenance

- Continuously improve docs as new platform knowledge is gained
- Follow the governance workflow in `REPOSITORY.md`:
  Issue → Branch → PR → CI → Merge → Monitor → Cleanup
- Branch naming: `docs/<issue>-desc`, `feature/<issue>-desc`,
  `fix/<issue>-desc`
- Conventional commits: `docs:`, `feat:`, `fix:`
- Many repo files are managed by `docs-control` — do not modify them
  locally (see `REPOSITORY.md` for the full list)

### Build & Development

No local `package.json` — all build deps live in the Docker image.

**Dev server** (live reload requires container restart):

```bash
docker run --rm -it \
  -v "$(pwd)/docs:/content/docs" \
  -p 4321:4321 \
  -e MODE=dev \
  ghcr.io/f5xc-salesdemos/docs-builder:latest
```

**Production build:**

```bash
docker run --rm \
  -v "$(pwd)/docs:/content/docs:ro" \
  -v "$(pwd)/output:/output" \
  -e GITHUB_REPOSITORY="f5xc-salesdemos/csd" \
  ghcr.io/f5xc-salesdemos/docs-builder:latest
```

**Serve build:** `npx serve output/ -l 8080` → `http://localhost:8080/csd/`

**CI lint:** Super Linter (markdownlint, yamllint, biome, codespell,
shellcheck, etc.)

### Content Authoring

**Content-only repo** — only the `docs/` directory matters. No
`astro.config.mjs`, no `package.json`.

**MDX Rules:**

- Bare `<` must be `&lt;`
- `{` and `}` must be `\{`/`\}` or backtick-wrapped
- Never use curly braces in `.mdx` filenames

**MDX imports:** Starlight components (`Aside`, `Steps`, `Code`) and
`Screenshot` from `@f5xc-salesdemos/docs-theme`.

**Screenshot Standards:**

| Type | Dimensions | DPR | Format |
| ---- | ---------- | --- | ------ |
| Page (XC console, web app) | 1600 x 900 | 1x | PNG |
| DevTools (console, network) | 1280 x 720 | 1x | PNG |

Full instructions in `SCREENSHOT-INSTRUCTIONS.md`.

**Dark Mode Conventions:**

| Source | Pattern |
| ------ | ------- |
| XC Console | Light only — `light="..."` (no `dark=`) |
| Juice Shop | Same image both modes — `light="..." dark="..."` with identical paths |
| DevTools | Light/dark pairs — `*-light.png` / `*-dark.png` |

### Shared Pipeline

| Repo | Role |
| ---- | ---- |
| `docs-theme` | Starlight plugin, layout, CSS, fonts |
| `docs-builder` | Docker image, build orchestration, npm deps |
| `docs-control` | CI workflows, governance, managed files |
| `docs-icons` | Iconify JSON icon sets, Astro icon components |

See `REPOSITORY.md` for the full pipeline details and content authoring
guide: <https://f5xc-salesdemos.github.io/docs-builder/content-authors/>
