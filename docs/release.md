# Release procedure

## Prepare

1. Confirm that CI passes on `main` and that the documented compatibility claims match completed validation.
2. Update release notes and the roadmap without promoting milestone 8B synthetic fixtures to empirical support.
3. Run `go test ./...`, `go test -race ./...`, `go vet ./...`, and formatting checks.
4. Complete every mandatory item in `docs/public-release-checklist.md`.
5. Create an annotated semantic-version tag from the reviewed `main` commit.

## Publish

Pushing a tag matching `v*` runs the release workflow. It retests the source and creates reproducible static Linux amd64 and arm64 packages with embedded version metadata:

- the standalone archive contains the binary, example configuration, JSON Schema, license, README, and documentation, with no service-manager files;
- the systemd archive contains the same payload plus the unit, sysusers, and tmpfiles examples.

The workflow generates `SHA256SUMS` and creates the GitHub release. Archive timestamps and ownership are normalized from the tagged commit so rebuilding the same source and toolchain inputs produces the same package payload.

Verify the selected archive against `SHA256SUMS`, run `audit2json --version`, and test `--check-config` before promoting it to production. Confirm that standalone archives contain no `packaging/` directory and that systemd archives contain all three files under `packaging/systemd/`.

## Roll back

Retain at least the previous release archive and configuration. Stop the collector cleanly, restore the previous binary, validate its configuration, and restart it against the existing version-1 checkpoint. At-least-once semantics mean a bounded replay is safer than manually advancing state.

Do not move or recreate a published tag. If a release is defective, mark it accordingly and publish a new patch version.
