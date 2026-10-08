#!/usr/bin/env bash
# Print release binary sizes per target (and the container image size when
# IMAGE is set). Uses the same flags as scripts/build-release.sh.
#   scripts/footprint.sh                 # Markdown table on stdout
#   IMAGE=hootway:dev scripts/footprint.sh
set -euo pipefail

targets=(linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64)
out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT

printf '| Target | Binary (bytes) | gzip -9 (bytes) |\n| --- | ---: | ---: |\n'
for target in "${targets[@]}"; do
  goos="${target%/*}" goarch="${target#*/}"
  bin="$out/hootway-$goos-$goarch"
  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" go build -buildvcs=false -trimpath \
    -ldflags="-s -w -buildid=" -o "$bin" ./cmd/hootway
  printf '| %s | %s | %s |\n' "$target" "$(wc -c <"$bin" | tr -d ' ')" "$(gzip -9n -c "$bin" | wc -c | tr -d ' ')"
done

if [[ -n "${IMAGE:-}" ]]; then
  printf '\nImage %s: %s bytes (uncompressed)\n' "$IMAGE" "$(docker image inspect "$IMAGE" --format '{{.Size}}')"
fi
