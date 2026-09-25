#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

shopt -s nullglob

runtime_sources=(
  docs/*/attack-scripts.mdx
  docs/*/trigger-detection.mdx
  docs/*/demo/phase-2-attack.mdx
  scripts/csd-traffic.mjs
  scripts/lib/csd-config.mjs
  scripts/lib/csd-scenarios.mjs
  scripts/lib/csd-runner.mjs
)

if [ "${#runtime_sources[@]}" -eq 0 ]; then
  echo "FAIL: no maintained runtime identity surfaces found" >&2
  exit 1
fi

python3 - "${runtime_sources[@]}" <<'PY'
from pathlib import Path
import re
import sys

checks = {
    "form or field values": re.compile(r"\b(?:field|form|input|password|email|card)(?:_|\s)*(?:value|values)\s*[:=]", re.I),
    "individual key values": re.compile(r"\b(?:key|keys|keystroke)(?:_|\s)*(?:value|values|buffer)\s*[:=]", re.I),
    "cookie values": re.compile(r"(?:document\.cookie|\bcookies?\s*[:=])", re.I),
    "authorization or token values": re.compile(r"\b(?:authorization|bearer|api[_-]?token|access[_-]?token|refresh[_-]?token)\s*[:=](?![ \t]*(?:APIToken[ \t]+)?xXCSH_[A-Z0-9_]+x\b)[ \t]*", re.I),
    "request or response bodies": re.compile(r"\b(?:postData|requestBody|responseBody)\s*[:=]", re.I),
    "browser storage values": re.compile(r"(?:localStorage|sessionStorage)\.(?:getItem|setItem)|\bstorage(?:_|\s)*values?\s*[:=]", re.I),
    "identity-bearing location": re.compile(r"window\.location\.href"),
    "known synthetic credential": re.compile(r"P@ssword123"),
}

sensitive_fixtures = {
    "form or field values": "field_value = synthetic_marker",
    "individual key values": "keyBuffer = synthetic_marker",
    "cookie values": "document.cookie",
    "authorization or token values": "authorization = synthetic_marker",
    "request or response bodies": "requestBody = synthetic_marker",
    "browser storage values": "localStorage.getItem('synthetic-key')",
    "identity-bearing location": "window.location.href",
    "known synthetic credential": "P@ssword123",
}
for label, fixture in sensitive_fixtures.items():
    if not checks[label].search(fixture):
        raise SystemExit(f"FAIL: runtime identity detector does not reject {label}")

findings = []
for name in sys.argv[1:]:
    path = Path(name)
    text = path.read_text(errors="replace")
    for label, pattern in checks.items():
        if label in {
            "authorization or token values",
            "request or response bodies",
            "browser storage values",
        } and (path.suffix == ".mdx" or path.name == "csd-traffic.mjs"):
            continue
        for match in pattern.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            findings.append(f"{path}:{line}: {label}")

if findings:
    raise SystemExit("FAIL: runtime demo content may retain identity-bearing values:\n" + "\n".join(findings))
PY

scenario_source=scripts/lib/csd-scenarios.mjs
runner_source=scripts/lib/csd-runner.mjs
node_test=tests/test-csd-traffic.mjs
for file in "$scenario_source" "$runner_source" "$node_test"; do
  if [ ! -f "$file" ]; then
    echo "FAIL: required traffic-generator surface is missing: $file" >&2
    exit 1
  fi
done

alternate_sources=(
  scripts/csd-violation-generator.mjs
  scripts/lib/csd-violation-scenarios.mjs
  tests/test-csd-violation-generator.mjs
)
for file in "${alternate_sources[@]}"; do
  if [ -e "$file" ]; then
    echo "FAIL: alternate traffic-generator surface remains: $file" >&2
    exit 1
  fi
done

scenario_names=(
  login-credential-skimmer
  registration-harvester
  payment-overlay-card-skimmer
  obfuscated-loader
  multi-cdn-injection
  tag-manager-hijack
  multi-channel-exfiltration
  high-volume-domain-exfiltration
  form-overlay
  keylogger-simulation
  maximum-detection
)
for scenario in "${scenario_names[@]}"; do
  grep -Fq -- "$scenario" "$scenario_source" || {
    echo "FAIL: canonical scenario library lacks $scenario" >&2
    exit 1
  }
done

for marker in field_values_discarded key_values_discarded; do
  grep -Fq -- "$marker" "$scenario_source" || {
    echo "FAIL: canonical scenario library lacks $marker receipt contract" >&2
    exit 1
  }
done

for forbidden in '--poll-csd' XCSH_API_TOKEN 'Authorization: `APIToken' detected_domains formFields; do
  if grep -Fq -- "$forbidden" "$runner_source"; then
    echo "FAIL: runner retains unsupported raw API polling surface: $forbidden" >&2
    exit 1
  fi
done

for contract in operation_index attempt_index kind outcome destination_host status; do
  grep -Fq -- "$contract" "$runner_source" "$scenario_source" || {
    echo "FAIL: traffic receipt lacks per-attempt $contract evidence" >&2
    exit 1
  }
done

for marker in run-start completed terminal; do
  grep -Fq -- "$marker" "$scenario_source" || {
    echo "FAIL: scenario runtime lacks required $marker binding marker" >&2
    exit 1
  }
done

grep -Eq 'schema[_ ]?version|schemaVersion' "$runner_source" || {
  echo "FAIL: runner lacks a versioned receipt contract" >&2
  exit 1
}
grep -Eq 'run[_ ]?id|runId' "$runner_source" "$scenario_source" || {
  echo "FAIL: traffic generator lacks run-scoped receipt identity" >&2
  exit 1
}
grep -Eq 'JSON\.stringify|serialized receipt|receipt' "$node_test" || {
  echo "FAIL: Node tests do not inspect serialized receipts" >&2
  exit 1
}

echo "PASS: runtime demos and traffic receipts discard identity-bearing values"
