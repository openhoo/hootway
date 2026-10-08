#!/usr/bin/env bash
# Regenerate the embedded, precompressed console assets after editing
# internal/gateway/web/*.{html,css,js}. Output is deterministic (gzip -9n).
set -euo pipefail
cd "$(dirname "$0")/../internal/gateway/web"
for f in *.html *.css *.js; do
  gzip -9nc -- "$f" > "$f.gz"
done
