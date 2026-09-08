#!/usr/bin/env bash

set -euo pipefail
umask 022

if [ "$#" -ne 4 ]; then
  echo "usage: $0 VERSION COMMIT SOURCE_DATE_EPOCH OUTPUT_DIRECTORY" >&2
  exit 2
fi

version=$1
commit=$2
source_date_epoch=$3
output_directory=$4

case "$source_date_epoch" in
  ''|*[!0-9]*)
    echo "SOURCE_DATE_EPOCH must be a non-negative integer" >&2
    exit 2
    ;;
esac

if [[ ! "$version" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || [[ ! "$commit" =~ ^[0-9a-f]{40}$ ]]; then
  echo "invalid version or full commit hash" >&2
  exit 2
fi
export GOTOOLCHAIN=local GOENV=off GOWORK=off GOFLAGS= GOEXPERIMENT= GOAMD64=v1 GOARM64=v8.0
expected_go="go$(cat .go-version)"
if [ "$(go env GOVERSION)" != "$expected_go" ]; then
  echo "release builds require $expected_go from .go-version" >&2
  exit 1
fi
# Never mix stale archives or directory payloads into a release.
if [ -d "$output_directory" ] && [ -n "$(find "$output_directory" -mindepth 1 -print -quit)" ]; then
  echo "output directory must be empty" >&2
  exit 1
fi
build_date=$(date -u -d "@${source_date_epoch}" +%Y-%m-%dT%H:%M:%SZ)
mkdir -p "$output_directory"

for arch in amd64 arm64; do
  base="aesirguard-audit_${version}_linux_${arch}"
  standalone="${base}_standalone"
  systemd="${base}_systemd"

  mkdir -p "${output_directory}/${standalone}/configs"

  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -buildvcs=false \
    -ldflags="-s -w -X 'main.releaseIdentity=ag-audit ${version} commit=${commit} built=${build_date} go=${expected_go}'" \
    -o "${output_directory}/${standalone}/ag-audit" ./cmd/ag-audit

  binary_sha=$(sha256sum "${output_directory}/${standalone}/ag-audit" | cut -d ' ' -f 1)
  printf '{"product":"AesirGuard Audit","binary":"ag-audit","version":"%s","commit":"%s","build_date":"%s","go":"%s","arch":"%s","binary_sha256":"%s"}\n' \
    "$version" "$commit" "$build_date" "$expected_go" "$arch" "$binary_sha" > "${output_directory}/${standalone}/BUILD-INFO.json"

  cp LICENSE README.md CHANGELOG.md CONTRIBUTING.md SECURITY.md "${output_directory}/${standalone}/"
  cp configs/aesirguard-audit.example.json "${output_directory}/${standalone}/configs/"
  cp -R docs schema "${output_directory}/${standalone}/"

  cp -R "${output_directory}/${standalone}" "${output_directory}/${systemd}"
  mkdir -p "${output_directory}/${systemd}/packaging"
  cp -R packaging/systemd "${output_directory}/${systemd}/packaging/"

  test ! -e "${output_directory}/${standalone}/packaging"
  test -f "${output_directory}/${standalone}/configs/aesirguard-audit.example.json"
  test -f "${output_directory}/${standalone}/schema/aesirguard-audit-v1.schema.json"
  test -f "${output_directory}/${systemd}/packaging/systemd/aesirguard-audit.service"
  test -f "${output_directory}/${systemd}/packaging/systemd/README.md"

  find "${output_directory}/${standalone}" "${output_directory}/${systemd}" \
    -type d -exec chmod 0755 {} +
  find "${output_directory}/${standalone}" "${output_directory}/${systemd}" \
    -type f -exec chmod 0644 {} +
  chmod 0755 \
    "${output_directory}/${standalone}/ag-audit" \
    "${output_directory}/${systemd}/ag-audit"

  tar --sort=name --mtime="@${source_date_epoch}" --owner=0 --group=0 --numeric-owner \
    -C "$output_directory" -cf - "$standalone" | gzip -n > "${output_directory}/${standalone}.tar.gz"
  tar --sort=name --mtime="@${source_date_epoch}" --owner=0 --group=0 --numeric-owner \
    -C "$output_directory" -cf - "$systemd" | gzip -n > "${output_directory}/${systemd}.tar.gz"

  rm -rf "${output_directory:?}/${standalone}" "${output_directory:?}/${systemd}"
done

(
  cd "$output_directory"
  sha256sum ./*.tar.gz > SHA256SUMS
)
