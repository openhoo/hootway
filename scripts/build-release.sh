#!/usr/bin/env bash
set -euo pipefail

version="${VERSION:?VERSION is required (semantic, without v)}"
commit="${COMMIT:-$(git rev-parse HEAD)}"
source_date_epoch="${SOURCE_DATE_EPOCH:-$(git show -s --format=%ct HEAD)}"
dist_dir="${DIST_DIR:-$(pwd)/dist}"

if [[ ! "$version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$ ]]; then
  echo "VERSION must be semantic without a v prefix" >&2
  exit 2
fi
if ! tar --version 2>/dev/null | grep -q 'GNU tar'; then
  echo "reproducible archives need GNU tar (gtar on macOS)" >&2
  exit 2
fi
if [[ -n "$(git status --porcelain --untracked-files=normal)" ]]; then
  echo "release builds require a clean worktree" >&2
  exit 2
fi

mkdir -p "$dist_dir"
temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT

build_one() {
  local goos="$1" goarch="$2" suffix="$3"
  local name="hootway_${version}_${goos}_${goarch}"
  local stage="$temporary/$name"
  mkdir -p "$stage"
  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" go build -buildvcs=false -trimpath \
    -ldflags="-s -w -buildid= -X main.version=${version} -X main.commit=${commit}" \
    -o "$stage/hootway${suffix}" ./cmd/hootway
  # Ship only what a user needs: the binary, licence, quick start and example config.
  cp LICENSE README.md "$stage/"
  mkdir -p "$stage/examples"
  cp examples/*.json "$stage/examples/"
  find "$stage" -exec touch -h -d "@${source_date_epoch}" {} + 2>/dev/null || find "$stage" -exec touch --date="@${source_date_epoch}" {} +
  if [[ "$goos" == "windows" ]]; then
    (cd "$temporary" && find "$name" -type f -print | LC_ALL=C sort | zip -X -q -9 "$dist_dir/${name}.zip" -@)
  else
    tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@${source_date_epoch}" \
      -cf - -C "$temporary" "$name" | gzip -9n >"$dist_dir/${name}.tar.gz"
  fi
}

build_one linux amd64 ""
build_one linux arm64 ""
build_one darwin amd64 ""
build_one darwin arm64 ""
build_one windows amd64 ".exe"
