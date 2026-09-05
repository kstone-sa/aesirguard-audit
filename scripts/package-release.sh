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

build_date=$(date -u -d "@${source_date_epoch}" +%Y-%m-%dT%H:%M:%SZ)
mkdir -p "$output_directory"

for arch in amd64 arm64; do
  base="audit2json_${version}_linux_${arch}"
  standalone="${base}_standalone"
  systemd="${base}_systemd"

  mkdir -p "${output_directory}/${standalone}/configs"

  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -buildvcs=false \
    -ldflags="-s -w -X main.version=${version} -X main.commit=${commit} -X main.buildDate=${build_date}" \
    -o "${output_directory}/${standalone}/audit2json" ./cmd/audit2json

  cp LICENSE README.md "${output_directory}/${standalone}/"
  cp configs/audit2json.example.json "${output_directory}/${standalone}/configs/"
  cp -R docs schema "${output_directory}/${standalone}/"

  cp -R "${output_directory}/${standalone}" "${output_directory}/${systemd}"
  mkdir -p "${output_directory}/${systemd}/packaging"
  cp -R packaging/systemd "${output_directory}/${systemd}/packaging/"

  test ! -e "${output_directory}/${standalone}/packaging"
  test -f "${output_directory}/${standalone}/configs/audit2json.example.json"
  test -f "${output_directory}/${standalone}/schema/audit2json-v1.schema.json"
  test -f "${output_directory}/${systemd}/packaging/systemd/audit2json.service"

  find "${output_directory}/${standalone}" "${output_directory}/${systemd}" \
    -type d -exec chmod 0755 {} +
  find "${output_directory}/${standalone}" "${output_directory}/${systemd}" \
    -type f -exec chmod 0644 {} +
  chmod 0755 \
    "${output_directory}/${standalone}/audit2json" \
    "${output_directory}/${systemd}/audit2json"

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
