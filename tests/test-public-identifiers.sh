#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

set +e
audit=$(bash scripts/check-pii.sh --scope staged --mode audit --format json)
rc=$?
set -e
if [ "$rc" -eq 2 ]; then
  echo "FAIL: managed PII audit could not run" >&2
  exit 1
fi

count=$(jq '[.findings[] | select(.category == "public-ip-review")] | length' <<<"$audit")
if [ "$count" -ne 0 ]; then
  echo "FAIL: tracked content contains ${count} routable public-IP example finding(s)" >&2
  exit 1
fi

python3 - <<'PY'
from pathlib import Path
import re
import subprocess
import tempfile

root = Path(".")
values = {}
for line in (root / ".env.example").read_text().splitlines():
    if line and not line.startswith("#") and "=" in line:
        key, value = line.split("=", 1)
        values[key] = value

required = {
    "XCSH_API_TOKEN",
    "XCSH_API_URL",
    "XCSH_EMAIL",
    "XCSH_CSD_DEPLOYMENT_MODE",
    "XCSH_NAMESPACE",
    "XCSH_DOMAINNAME",
    "XCSH_ROOT_DOMAIN",
    "XCSH_LB_NAME",
    "XCSH_ORIGIN_KIND",
    "XCSH_ORIGIN_HOSTNAME",
    "XCSH_ORIGIN_IP",
    "XCSH_APPLICATION_MARKER",
    "XCSH_ORIGIN_POOL",
    "XCSH_ORIGIN_PORT",
    "XCSH_HC_NAME",
}
missing = required - values.keys()
if missing:
    raise SystemExit(f"FAIL: .env.example lacks required XCSH keys: {sorted(missing)}")
if values["XCSH_CSD_DEPLOYMENT_MODE"] not in {"api", "terraform"}:
    raise SystemExit("FAIL: deployment mode must select api or terraform ownership")
if values["XCSH_LB_NAME"] != "client-side-defense":
    raise SystemExit("FAIL: XCSH_LB_NAME must be the unsuffixed canonical load balancer name")
if values["XCSH_ORIGIN_KIND"] != "public_name":
    raise SystemExit("FAIL: XCSH_ORIGIN_KIND must default to public_name")
if values["XCSH_ORIGIN_HOSTNAME"] != "origin.example.com":
    raise SystemExit("FAIL: public_name must use the non-routable origin.example.com placeholder")
if values["XCSH_ORIGIN_IP"]:
    raise SystemExit("FAIL: XCSH_ORIGIN_IP must be empty when public_name is selected")
if values["XCSH_APPLICATION_MARKER"] != "OWASP Juice Shop":
    raise SystemExit("FAIL: XCSH_APPLICATION_MARKER must default to the repository reference marker")

source_suffixes = {
    ".cjs", ".hcl", ".ini", ".json", ".md", ".mdx", ".py", ".sh",
    ".tf", ".toml", ".txt", ".yaml", ".yml",
}
maintained_prefixes = ("docs/en/", "docs/_imports/", ".github/", "scripts/", "tests/", "terraform/")
terraform_artifacts = {".terraform", "terraform.tfstate.d"}


def maintained_sources(repo):
    names = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.split("\0")
    paths = []
    for name in names:
        if not name:
            continue
        path = Path(name)
        if any(part in terraform_artifacts for part in path.parts):
            continue
        if path.name == "crash.log" or ".tfstate" in path.name or path.suffix == ".tfplan":
            continue
        is_root_surface = len(path.parts) == 1 and (path.suffix in source_suffixes or name == ".env.example")
        is_import_map = name == "docs/_imports"
        is_maintained_tree = name.startswith(maintained_prefixes) and path.suffix in source_suffixes
        if is_root_surface or is_import_map or is_maintained_tree:
            paths.append(repo / path)
    return paths


old_prefix = "F5" + "XC_"
old_token_prefix = "xF5" + "XC_"
bare_mode = "CSD_" + "DEPLOYMENT_MODE"
retired_host = "botdemo" + ".sales-demo.f5demos.com"
retired_namespace = "bot-" + "defense"
legacy_api = "docs.cloud.f5.com/" + "docs-v2/api"
checks = [
    ("legacy F5XC environment prefix", re.compile(rf"(?<![A-Za-z0-9_]){re.escape(old_prefix)}")),
    ("legacy xF5XC placeholder prefix", re.compile(re.escape(old_token_prefix))),
    ("unprefixed deployment-mode variable", re.compile(rf"(?<![A-Z0-9_]){re.escape(bare_mode)}\b")),
    ("retired demo hostname", re.compile(re.escape(retired_host), re.IGNORECASE)),
    ("retired namespace", re.compile(rf"\b{re.escape(retired_namespace)}\b", re.IGNORECASE)),
    (
        "suffixed XCSH load balancer name",
        re.compile(r"(?:XCSH|xXCSH)_LB_NAME(?:[_-](?:HTTP|HTTPS|PRIMARY|SECONDARY|[12])|[12]\b)", re.IGNORECASE),
    ),
    (
        "two-load-balancer architecture claim",
        re.compile(
            r"\b(?:two|2)\s+(?:F5\s+XC\s+)?(?:HTTP\s+and\s+HTTPS\s+)?(?:load balancers?|LBs?)\b"
            r"|\bHTTP[- ]primary\b|\bHTTPS[- ]secondary\b",
            re.IGNORECASE,
        ),
    ),
    ("deprecated API documentation link", re.compile(re.escape(legacy_api), re.IGNORECASE)),
]


def legacy_findings(paths):
    findings = []
    for path in paths:
        text = path.read_text(errors="replace")
        for label, pattern in checks:
            for match in pattern.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                findings.append(f"{path}:{line}: {label}")
    return findings


findings = legacy_findings(maintained_sources(root))
if findings:
    raise SystemExit("FAIL: retired or contradictory public identifiers found:\n" + "\n".join(findings))

# Every newly admitted text format, including the extensionless import map, must
# fail closed while it is still an intended, non-ignored untracked source.
fixture_names = (
    "scripts/fixture.py",
    "scripts/fixture.cjs",
    "scripts/fixture.toml",
    "scripts/fixture.ini",
    "scripts/fixture.txt",
    "docs/_imports",
)
with tempfile.TemporaryDirectory() as directory:
    fixture_root = Path(directory)
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=fixture_root, check=True)
    for fixture_name in fixture_names:
        fixture = fixture_root / fixture_name
        fixture.parent.mkdir(parents=True, exist_ok=True)
        fixture.write_text(old_prefix + "FIXTURE=value\n")
        fixture_findings = legacy_findings(maintained_sources(fixture_root))
        if not any(str(fixture) in finding for finding in fixture_findings):
            raise SystemExit(f"FAIL: maintained-source inventory skipped untracked fixture {fixture_name}")
        fixture.unlink()
demo = (root / "docs/en/demo/index.mdx").read_text()
if re.search(r"PF-T3-skip|then \"SKIP\"", demo):
    raise SystemExit("FAIL: a placeholder origin can bypass readiness checks")
if "**Origin contract guard:**" not in demo:
    raise SystemExit("FAIL: docs/en/demo/index.mdx lacks the origin contract guard")
if not re.search(r"origin\.example\.com.*192\.0\.2\.\*.*198\.51\.100\.\*.*203\.0\.113\.\*", demo):
    raise SystemExit("FAIL: origin guard does not reject hostname and TEST-NET placeholders")

diagnostics = (root / "docs/en/diagnostics.mdx").read_text()
marker_contract = [
    r"APPLICATION_MARKER='xXCSH_APPLICATION_MARKERx'",
    r"XCSH_APPLICATION_MARKER is required for every scenario",
    r"replace-with-application-marker.*replace-with-azure-application-marker.*xXCSH_APPLICATION_MARKERx",
    r"grep -Fqi \"\$APPLICATION_MARKER\"",
]
for pattern in marker_contract:
    if not re.search(pattern, diagnostics, re.DOTALL):
        raise SystemExit(f"FAIL: diagnostics lacks origin-independent application-marker contract: {pattern}")
if re.search(r"(?:public_name|public_ip)\)[^\n]*APPLICATION_MARKER", diagnostics):
    raise SystemExit("FAIL: diagnostics must not infer application marker from origin kind")
PY

echo "PASS: maintained public identifiers and XCSH contracts are current"
