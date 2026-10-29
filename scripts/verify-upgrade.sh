#!/usr/bin/env bash
# Mandatory binary-only upgrade gate. The immutable pre-fix source produces the
# checkpoint itself; no reset, migration command, or configuration edit is used.
set -euo pipefail
cd "$(dirname "$0")/.."
baseline=7744d4e9a510f88ebf60af6f9723640e916c6083
git cat-file -e "$baseline^{commit}" || {
  echo 'Pre-fix source unavailable; fetch complete repository history before running this gate.' >&2
  exit 1
}
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
mkdir "$scratch/previous"
git archive "$baseline" | tar -x -C "$scratch/previous"
(cd "$scratch/previous" && go build -o "$scratch/pre-fix" ./cmd/ag-audit)
go build -o "$scratch/fixed" ./cmd/ag-audit
AG_AUDIT_PRE_FIX_BINARY="$scratch/pre-fix" AG_AUDIT_FIXED_BINARY="$scratch/fixed" \
  go test -count=1 ./cmd/ag-audit -run '^TestBinaryUpgradeFromFailedDeployment$' -v
