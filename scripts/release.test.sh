#!/usr/bin/env bash
set -euo pipefail

valid=(0.0.0 1.2.3 1.2.3-0 1.2.3-alpha.1 1.2.3-01a 1.2.3-rc-1 1.2.3-x-y.z)
invalid=(v1.2.3 01.2.3 1.02.3 1.2.03 1.2 1.2.3- 1.2.3-. 1.2.3-alpha.
  1.2.3-alpha..1 1.2.3-01 1.2.3-alpha.01 1.2.3+build 1.2.3-a_b $'1.2.3-a\n')

for version in "${valid[@]}"; do
  bash scripts/validate-version.sh "$version"
done
for version in "${invalid[@]}"; do
  if bash scripts/validate-version.sh "$version" 2>/dev/null; then
    echo "invalid release version was accepted" >&2
    exit 1
  fi
done
echo "release version regressions passed"
