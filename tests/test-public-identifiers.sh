#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

public_ip_audit() {
  local repo=${1:-$ROOT} scanner=${2:-${ROOT}/scripts/check-pii.sh}
  local audit_file rc=0
  audit_file=$(mktemp)
  (cd "$repo" && bash "$scanner" --scope staged --mode audit --format json) >"$audit_file" || rc=$?
  if [ "$rc" -eq 2 ]; then
    rm -f "$audit_file"
    echo "FAIL: managed PII audit could not run" >&2
    return 1
  fi
  if [ "$rc" -ne 0 ] && [ "$rc" -ne 1 ]; then
    rm -f "$audit_file"
    echo "FAIL: managed PII audit returned unexpected status ${rc}" >&2
    return 1
  fi

  if ! PYTHONPATH="${ROOT}/scripts" python3 - "$repo" "$audit_file" <<'PY'; then
from collections import Counter
import ipaddress
import json
from pathlib import Path
import subprocess
import sys

from check_pii import (
    ANSI_ESCAPE_RE,
    DOCUMENTATION_NETWORKS,
    DOTTED_VERSION_PREFIX_RE,
    IPV4_RE,
    MEDIA_SUFFIXES,
    PRINTABLE_ASCII_RE,
    SURROGATE_ESCAPE_BASE,
    SURROGATE_ESCAPE_C1_LAST,
    SURROGATE_ESCAPE_FIRST,
    SURROGATE_ESCAPE_LAST,
    SVG_PATH_ATTRIBUTE_RE,
    TEXT_MEDIA_SUFFIXES,
    invisible_format_character,
    is_excluded,
    looks_binary,
)

repo = Path(sys.argv[1])
audit_path = Path(sys.argv[2])

try:
    audit = json.loads(audit_path.read_text(encoding="utf-8"))
except (OSError, UnicodeError, json.JSONDecodeError) as error:
    raise SystemExit(f"FAIL: managed PII audit returned malformed JSON: {error}") from error
if not isinstance(audit, dict) or not isinstance(audit.get("findings"), list):
    raise SystemExit("FAIL: managed PII audit JSON lacks a findings array")
for finding in audit["findings"]:
    if not isinstance(finding, dict) or not isinstance(finding.get("category"), str):
        raise SystemExit("FAIL: managed PII audit JSON contains a malformed finding")

staged_paths = subprocess.run(
    [
        "git", "diff", "--cached", "--name-only", "-z", "--no-renames",
        "--no-ext-diff", "--diff-filter=ACMRTUXB", "--",
    ],
    cwd=repo, check=True, capture_output=True,
).stdout.split(b"\0")

def git_blob(spec):
    result = subprocess.run(
        ["git", "show", spec], cwd=repo, capture_output=True, check=False,
    )
    if result.returncode == 0:
        return result.stdout
    return None

def normalized_text(path, data):
    if is_excluded(path):
        return None
    suffix = Path(path).suffix.lower()
    if suffix in MEDIA_SUFFIXES - TEXT_MEDIA_SUFFIXES:
        return None
    if looks_binary(data):
        printable = data.replace(b"\0", b"")
        return "\n".join(
            match.group(0).decode("ascii")
            for match in PRINTABLE_ASCII_RE.finditer(printable)
        )
    decoded = data.decode("utf-8", "surrogateescape")
    text = []
    for character in decoded:
        codepoint = ord(character)
        if SURROGATE_ESCAPE_FIRST <= codepoint <= SURROGATE_ESCAPE_C1_LAST:
            text.append(chr(codepoint - SURROGATE_ESCAPE_BASE))
        elif not SURROGATE_ESCAPE_FIRST <= codepoint <= SURROGATE_ESCAPE_LAST:
            text.append(character)
    visible = (
        char for char in ANSI_ESCAPE_RE.sub("", "".join(text))
        if not invisible_format_character(char)
    )
    return "".join(visible)

def public_ip_occurrences(path, data):
    text = normalized_text(path, data)
    if text is None:
        return Counter()
    occurrences = Counter()
    for line in text.splitlines():
        for match in IPV4_RE.finditer(line):
            try:
                address = ipaddress.ip_address(match.group(0))
            except ValueError:
                continue
            if not address.is_global or address.is_multicast:
                continue
            if any(address in network for network in DOCUMENTATION_NETWORKS):
                continue
            prefix = line[max(0, match.start() - 96):match.start()]
            if DOTTED_VERSION_PREFIX_RE.search(prefix):
                continue
            for attribute in SVG_PATH_ATTRIBUTE_RE.finditer(line, 0, match.start()):
                value = line[attribute.end():match.start()]
                if attribute.group("quote") not in value:
                    break
            else:
                attribute = None
            if attribute is not None:
                continue
            occurrences[(path, str(address))] += 1
    return occurrences

staged = Counter()
head = Counter()
for encoded_path in staged_paths:
    if not encoded_path:
        continue
    path = encoded_path.decode("utf-8", "surrogateescape")
    staged_blob = git_blob(f":{path}")
    if staged_blob is None:
        raise SystemExit(f"FAIL: cannot read staged blob for {path}")
    staged.update(public_ip_occurrences(path, staged_blob))
    head_blob = git_blob(f"HEAD:{path}")
    if head_blob is not None:
        head.update(public_ip_occurrences(path, head_blob))

additions = staged - head
if additions:
    count = sum(additions.values())
    details = ", ".join(
        f"{path} ({amount} new occurrence{'s' if amount != 1 else ''})"
        for (path, _value), amount in sorted(additions.items())
    )
    raise SystemExit(
        f"FAIL: staged content introduces {count} routable public-IP "
        f"example finding(s): {details}"
    )
PY
    rm -f "$audit_file"
    return 1
  fi
  rm -f "$audit_file"
}

public_ip_audit "$ROOT"

PUBLIC_IP_A=$(printf '8.8.%s' '8.8')
PUBLIC_IP_B=$(printf '1.1.%s' '1.1')
IP_TEST_WORK=$(mktemp -d)
cleanup_ip_tests() { rm -rf "$IP_TEST_WORK"; }
trap cleanup_ip_tests EXIT

new_ip_test_repo() {
  local name=$1 repo="${IP_TEST_WORK}/$1"
  mkdir -p "$repo"
  git -C "$repo" init -q -b main
  git -C "$repo" config user.email test@example.com
  git -C "$repo" config user.name "Public IP Audit Test"
  printf '# fixture\n' >"${repo}/fixture.tf"
  git -C "$repo" add fixture.tf
  git -C "$repo" commit -qm baseline
  printf '%s' "$repo"
}

assert_ip_audit_passes() {
  local label=$1 repo=$2
  if public_ip_audit "$repo" >/dev/null 2>&1; then
    echo "[OK] $label -> accepted"
  else
    echo "FAIL: $label was rejected" >&2
    exit 1
  fi
}

assert_ip_audit_fails() {
  local label=$1 repo=$2 scanner=${3:-${ROOT}/scripts/check-pii.sh}
  if public_ip_audit "$repo" "$scanner" >/dev/null 2>&1; then
    echo "FAIL: $label was accepted" >&2
    exit 1
  else
    echo "[OK] $label -> rejected"
  fi
}

repo=$(new_ip_test_repo unchanged-shifted)
printf 'allowed = "%s/32"\n' "$PUBLIC_IP_A" >"${repo}/fixture.tf"
git -C "$repo" add fixture.tf
git -C "$repo" commit -qm public-ip-baseline
printf '# unrelated line shift\nallowed = "%s/32"\n' "$PUBLIC_IP_A" >"${repo}/fixture.tf"
git -C "$repo" add fixture.tf
assert_ip_audit_passes "unchanged CIDR with unrelated line shift" "$repo"

repo=$(new_ip_test_repo new-file)
printf 'address = "%s"\n' "$PUBLIC_IP_A" >"${repo}/new.tf"
git -C "$repo" add new.tf
assert_ip_audit_fails "routable IP in newly staged file" "$repo"

repo=$(new_ip_test_repo duplicate)
printf 'address = "%s"\n' "$PUBLIC_IP_A" >"${repo}/fixture.tf"
git -C "$repo" add fixture.tf
git -C "$repo" commit -qm public-ip-baseline
printf 'first = "%s"\nsecond = "%s"\n' "$PUBLIC_IP_A" "$PUBLIC_IP_A" >"${repo}/fixture.tf"
git -C "$repo" add fixture.tf
assert_ip_audit_fails "duplicate occurrence of existing IP" "$repo"

repo=$(new_ip_test_repo replacement)
printf 'address = "%s"\n' "$PUBLIC_IP_A" >"${repo}/fixture.tf"
git -C "$repo" add fixture.tf
git -C "$repo" commit -qm public-ip-baseline
printf 'address = "%s"\n' "$PUBLIC_IP_B" >"${repo}/fixture.tf"
git -C "$repo" add fixture.tf
assert_ip_audit_fails "replacement with different IP" "$repo"

repo=$(new_ip_test_repo removal)
printf 'first = "%s"\nsecond = "%s"\n' "$PUBLIC_IP_A" "$PUBLIC_IP_A" >"${repo}/fixture.tf"
git -C "$repo" add fixture.tf
git -C "$repo" commit -qm public-ip-baseline
printf 'first = "%s"\n' "$PUBLIC_IP_A" >"${repo}/fixture.tf"
git -C "$repo" add fixture.tf
assert_ip_audit_passes "removed public-IP occurrence" "$repo"

repo=$(new_ip_test_repo malformed-output)
printf '# staged edit\n' >>"${repo}/fixture.tf"
git -C "$repo" add fixture.tf
malformed_scanner="${IP_TEST_WORK}/malformed-scanner.sh"
printf '#!/usr/bin/env bash\nprintf "{malformed\\n"\nexit 1\n' >"$malformed_scanner"
assert_ip_audit_fails "malformed scanner output" "$repo" "$malformed_scanner"

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
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
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
    ".cjs", ".hcl", ".ini", ".json", ".md", ".mdx", ".mjs", ".py", ".sh",
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
    "scripts/fixture.mjs",
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
    authorized_fixture = fixture_root / "scripts/authorized-target.mjs"
    authorized_fixture.write_text("export const target = 'https://client-side-defense.f5-sales-demo.com/';\n")
    authorized_findings = legacy_findings(maintained_sources(fixture_root))
    if any(str(authorized_fixture) in finding for finding in authorized_findings):
        raise SystemExit("FAIL: required authorized public traffic identifier was rejected")
config_sources = (
    root / "scripts/csd-traffic.mjs",
    root / "scripts/lib/csd-config.mjs",
    root / "scripts/lib/csd-scenarios.mjs",
    root / "scripts/lib/csd-runner.mjs",
)
for config_source in config_sources:
    if not config_source.is_file():
        raise SystemExit(f"FAIL: {config_source} is required for traffic target authorization")
config_text = "\n".join(path.read_text(errors="replace") for path in config_sources)
required_traffic_identifiers = (
    "client-side-defense.f5-sales-demo.com",
)
for identifier in required_traffic_identifiers:
    if identifier not in config_text:
        raise SystemExit(f"FAIL: CSD traffic config lacks required public identifier: {identifier}")
generator_text = "\n".join(path.read_text(errors="replace") for path in config_sources)
if re.search(r"allowHosts\.(?:some|find)\s*\(|allowedHosts\.(?:some|find)\s*\(", generator_text):
    raise SystemExit("FAIL: traffic target authorization must use exact-host membership, not collection predicates")

scenario_text = (root / "scripts/lib/csd-scenarios.mjs").read_text(errors="replace")
if "tagManager: 'reviewed-tag-manager-simulation'" not in scenario_text:
    raise SystemExit("FAIL: tag-manager scenario lacks reviewed tag metadata")
if "dataset.tagManager" not in scenario_text:
    raise SystemExit("FAIL: runtime does not apply tag-manager metadata to its script element")

high_volume = re.search(
    r"'high-volume-domain-exfiltration':\s*define\(\{[\s\S]*?boundary:\s*'High volume[^\n]+\n\s*\}\),",
    scenario_text,
    re.MULTILINE,
 )
if not high_volume:
    raise SystemExit("FAIL: high-volume scenario definition is missing")
if len(re.findall(r"kind:\s*'fetch'", high_volume.group(0))) != 2:
    raise SystemExit("FAIL: high-volume manifest must define exactly two POST operations")
if "...injectCdn()" not in high_volume.group(0) or high_volume.group(0).count("kind: 'inject-script'") != 1:
    raise SystemExit("FAIL: high-volume manifest must preserve five script attempts")
documentation = (root / "docs/en/attack-scripts.mdx").read_text(errors="replace")
high_volume_row = next((line for line in documentation.splitlines() if "`high-volume-domain-exfiltration`" in line), "")
for phrase in ("five", "two", "seven"):
    if phrase not in high_volume_row.lower():
        raise SystemExit(f"FAIL: high-volume documentation lacks manifest parity term: {phrase}")


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
