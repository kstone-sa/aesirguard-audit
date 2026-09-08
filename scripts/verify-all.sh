#!/usr/bin/env bash
# Shared main/tag quality gate. Run from repository root with pinned Go and
# Python/jsonschema available. The output directory must initially be absent/empty.
set -euo pipefail
if [ "$#" -ne 4 ]; then
  echo "usage: $0 VERSION COMMIT SOURCE_DATE_EPOCH OUTPUT_DIRECTORY" >&2
  exit 2
fi
version=$1
commit=$2
source_date_epoch=$3
dist=$4
export GOTOOLCHAIN=local GOENV=off GOWORK=off GOFLAGS= GOEXPERIMENT= GOAMD64=v1 GOARM64=v8.0
[ "$(go env GOVERSION)" = "go$(cat .go-version)" ]
unformatted=$(gofmt -l .)
if [ -n "$unformatted" ]; then
  printf '%s\n' "$unformatted" >&2
  exit 1
fi
python3 scripts/check-branding.py
git diff --check
go test -count=1 ./...
go test -race -count=1 ./...
go vet ./...
govulncheck ./...
go test ./internal/audit -run '^$' -fuzz '^FuzzParseRecordDoesNotPanic$' -fuzztime=5s -parallel=2
go test ./internal/audit -run '^$' -fuzz '^FuzzAssemblerPreservesAcceptedRecords$' -fuzztime=5s -parallel=2
go test ./internal/audit -run '^$' -bench '^BenchmarkAuditPipeline$' -benchtime=200ms -benchmem
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
go build -o "$scratch/ag-audit" ./cmd/ag-audit
python3 scripts/validate-schema.py "$scratch/ag-audit"
./scripts/package-release.sh "$version" "$commit" "$source_date_epoch" "$dist"
./scripts/verify-release.sh "$dist" "$version" "$commit" "$source_date_epoch"
python3 scripts/test-release-verifier.py "$dist" "$version" "$commit" "$source_date_epoch"
# Check reproducibility with restrictive source modes as well as caller umask,
# without modifying the checkout used by subsequent verification steps.
mkdir "$scratch/source"
for item in go.mod .go-version cmd internal data LICENSE README.md CHANGELOG.md CONTRIBUTING.md SECURITY.md configs docs schema packaging scripts; do
  cp -R "$item" "$scratch/source/"
done
chmod -R go-rwx "$scratch/source"
(cd "$scratch/source" && umask 077 && ./scripts/package-release.sh "$version" "$commit" "$source_date_epoch" "$scratch/rebuilt")
cmp "$dist/SHA256SUMS" "$scratch/rebuilt/SHA256SUMS"
echo 'All main/tag verification gates passed, including reproducible package checksums'
