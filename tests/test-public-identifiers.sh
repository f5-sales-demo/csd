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
import ipaddress
from pathlib import Path

line = next(
    line
    for line in Path(".env.example").read_text().splitlines()
    if line.startswith("F5XC_ORIGIN_IP=")
)
origin = ipaddress.ip_address(line.partition("=")[2])
if origin not in ipaddress.ip_network("198.51.100.0/24"):
    raise SystemExit("FAIL: F5XC_ORIGIN_IP is not in the origin-role TEST-NET-2 range")
PY

rg --quiet '^\| `F5XC_ORIGIN_IP` \| \*\*Yes\*\* \| — \| `198\.51\.100\.10` \|$' \
  DEMO_READINESS_MATRIX.md || {
  echo "FAIL: TEST-NET origin is not treated as a required override" >&2
  exit 1
}

if rg --quiet 'PF-T3-skip|then "SKIP"' docs/*/demo/index.mdx; then
  echo "FAIL: a TEST-NET origin can bypass readiness checks" >&2
  exit 1
fi

for file in docs/*/demo/index.mdx; do
  rg --quiet 'check: "PF-T3-origin-guard"' "$file" || {
    echo "FAIL: $file lacks the TEST-NET origin guard" >&2
    exit 1
  }
done

echo "PASS: public identifiers use documentation-reserved values"
