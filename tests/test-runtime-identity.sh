#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

targets=(
  docs/*/attack-scripts.mdx
  docs/*/trigger-detection.mdx
  docs/*/demo/phase-2-attack.mdx
  scripts/capture-console-output.cjs
)

unsafe='(credentials:[[:space:]]*harvested|data:[[:space:]]*(creds|data)|captured:[[:space:]]*existing|cookies:[[:space:]]*document\.cookie|key:[[:space:]]*e\.key|keys:[[:space:]]*keyBuffer|window\.location\.href|email[[:space:]]*\?[[:space:]]*email\.value|pw[[:space:]]*\?[[:space:]]*pw\.value|P@ssword123)'
if grep -Eq -- "$unsafe" "${targets[@]}"; then
  echo "FAIL: runtime demo content retains or exposes identity-bearing values" >&2
  exit 1
fi

for file in docs/*/attack-scripts.mdx; do
  grep -Eq 'field_values_discarded: true' "$file" || {
    echo "FAIL: $file lacks field-value discard markers" >&2
    exit 1
  }
  grep -Eq 'key_values_discarded: true' "$file" || {
    echo "FAIL: $file lacks key-value discard markers" >&2
    exit 1
  }
done

for file in docs/*/trigger-detection.mdx docs/*/demo/phase-2-attack.mdx; do
  grep -Eq 'field_values_discarded: true' "$file" || {
    echo "FAIL: $file lacks field-value discard markers" >&2
    exit 1
  }
done

echo "PASS: runtime demos discard identity-bearing values before logging or transport"
