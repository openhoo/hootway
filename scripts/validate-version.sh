#!/usr/bin/env bash
# Release versions: SemVer core and optional prerelease, without v or build metadata.
set -euo pipefail

version="${1:-}"
if [[ $# != 1 || ! "$version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$ ]]; then
  echo "release version must be major.minor.patch with an optional SemVer prerelease" >&2
  exit 2
fi
if [[ "$version" == *-* ]]; then
  IFS=. read -r -a identifiers <<< "${version#*-}"
  for identifier in "${identifiers[@]}"; do
    if [[ "$identifier" =~ ^[0-9]+$ && ${#identifier} -gt 1 && "$identifier" == 0* ]]; then
      echo "numeric prerelease identifiers must not have leading zeros" >&2
      exit 2
    fi
  done
fi
