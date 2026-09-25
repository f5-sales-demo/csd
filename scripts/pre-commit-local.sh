#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

if ! command -v node >/dev/null 2>&1; then
  echo "FAIL: Node.js 22 or newer is required for CSD traffic-generator tests" >&2
  exit 1
fi

node_major=$(node -p 'Number(process.versions.node.split(".")[0])')
if ! [[ "$node_major" =~ ^[0-9]+$ ]] || [ "$node_major" -lt 22 ]; then
  echo "FAIL: Node.js 22 or newer is required; found $(node --version)" >&2
  exit 1
fi

node --test tests/test-csd-traffic.mjs
bash tests/test-runtime-identity.sh
bash tests/test-public-identifiers.sh
