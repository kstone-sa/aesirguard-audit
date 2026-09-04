# Release procedure

## Prepare

1. Confirm that CI passes on `main` and that the documented compatibility claims match completed validation.
2. Update release notes and the roadmap without promoting milestone 8B synthetic fixtures to empirical support.
3. Run `go test ./...`, `go test -race ./...`, `go vet ./...`, and formatting checks.
4. Create an annotated semantic-version tag from the reviewed `main` commit.

## Publish

Pushing a tag matching `v*` runs the release workflow. It retests the source, builds static Linux amd64 and arm64 archives with embedded version metadata, includes the example configuration, systemd assets, and operational documentation, generates SHA-256 checksums, and creates the GitHub release.

Verify each archive against `SHA256SUMS`, run `audit2json --version`, and test `--check-config` before promoting it to production.

## Roll back

Retain at least the previous release archive and configuration. Stop the collector cleanly, restore the previous binary, validate its configuration, and restart it against the existing version-1 checkpoint. At-least-once semantics mean a bounded replay is safer than manually advancing state.

Do not move or recreate a published tag. If a release is defective, mark it accordingly and publish a new patch version.
