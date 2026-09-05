#!/usr/bin/env bash

set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $0 OUTPUT_DIRECTORY VERSION" >&2
  exit 2
fi

output_directory=$1
version=$2
standalone="${output_directory}/audit2json_${version}_linux_amd64_standalone.tar.gz"
systemd="${output_directory}/audit2json_${version}_linux_amd64_systemd.tar.gz"

test "$(find "$output_directory" -maxdepth 1 -name '*_standalone.tar.gz' | wc -l)" -eq 2
test "$(find "$output_directory" -maxdepth 1 -name '*_systemd.tar.gz' | wc -l)" -eq 2
(cd "$output_directory" && sha256sum -c SHA256SUMS)

tar -tzf "$standalone" | grep '/audit2json$' >/dev/null
if tar -tzf "$standalone" | grep '/packaging/' >/dev/null; then
  echo "standalone archive unexpectedly contains service-manager packaging" >&2
  exit 1
fi

for asset in audit2json.service audit2json.sysusers.conf audit2json.tmpfiles.conf; do
  tar -tzf "$systemd" | grep "/packaging/systemd/${asset}$" >/dev/null
done

verification_directory=$(mktemp -d)
cleanup() {
  rm -rf -- "$verification_directory"
}
trap cleanup EXIT

tar -xzf "$standalone" -C "$verification_directory"
package_root="${verification_directory}/audit2json_${version}_linux_amd64_standalone"
"${package_root}/audit2json" --version
"${package_root}/audit2json" \
  --config "${package_root}/configs/audit2json.example.json" --check-config
