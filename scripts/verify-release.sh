#!/usr/bin/env bash

set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 OUTPUT_DIRECTORY VERSION" >&2
  exit 2
fi

output_directory=$1
version=$2
test "$(find "$output_directory" -maxdepth 1 -name '*_standalone.tar.gz' | wc -l)" -eq 2
test "$(find "$output_directory" -maxdepth 1 -name '*_systemd.tar.gz' | wc -l)" -eq 2
(cd "$output_directory" && sha256sum -c SHA256SUMS)

verification_directory=$(mktemp -d)
cleanup() {
  rm -rf -- "$verification_directory"
}
trap cleanup EXIT

for arch in amd64 arm64; do
  standalone="${output_directory}/audit2json_${version}_linux_${arch}_standalone.tar.gz"
  systemd="${output_directory}/audit2json_${version}_linux_${arch}_systemd.tar.gz"

  tar -tzf "$standalone" | grep '/audit2json$' >/dev/null
  for asset in LICENSE README.md CHANGELOG.md CONTRIBUTING.md SECURITY.md; do
    tar -tzf "$standalone" | grep "/${asset}$" >/dev/null
  done
  if tar -tzf "$standalone" | grep '/packaging/' >/dev/null; then
    echo "standalone archive unexpectedly contains service-manager packaging" >&2
    exit 1
  fi

  for asset in README.md audit2json.service audit2json.sysusers.conf audit2json.tmpfiles.conf; do
    tar -tzf "$systemd" | grep "/packaging/systemd/${asset}$" >/dev/null
  done
done

tar -xzf "${output_directory}/audit2json_${version}_linux_amd64_standalone.tar.gz" \
  -C "$verification_directory"
package_root="${verification_directory}/audit2json_${version}_linux_amd64_standalone"
"${package_root}/audit2json" --version
"${package_root}/audit2json" --config \
  "${package_root}/configs/audit2json.example.json" --check-config
