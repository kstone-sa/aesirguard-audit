# Release procedure

## Prepare

1. Confirm that CI passes on `main` and that the documented compatibility claims match completed validation.
2. Update release notes and the roadmap without presenting synthetic fixtures as empirical distribution support.
3. Run `go test ./...`, `go test -race ./...`, `go vet ./...`, and formatting checks.
4. Complete every mandatory pre-tag item in `docs/public-release-checklist.md`.
5. Create an annotated semantic-version tag from the reviewed `main` commit.

## Publish

Pushing a tag matching `v*` runs the release workflow. It retests the source and creates reproducible static Linux amd64 and arm64 packages with embedded version metadata:

- the standalone archive contains the binary, example configuration, JSON Schema, license, public project policies, changelog, README, and documentation, with no service-manager files;
- the systemd archive contains the same payload plus the unit, sysusers, and tmpfiles examples.

The workflow generates `SHA256SUMS`, verifies the completed archives, and only then creates the GitHub release. Verification checks every checksum, the separation of standalone and systemd contents, all supplied systemd assets, both architecture binaries, and the example configuration. Archive timestamps, ownership, and permissions are normalized so rebuilding the same source and toolchain inputs produces the same package payload.

After publication, download the selected archive and `SHA256SUMS` from GitHub and verify them again before promoting the release. This final check covers the published download path in addition to the workflow's pre-publication verification.

## Roll back

Retain at least the previous release archive and configuration. Stop the collector cleanly, restore the previous binary, validate its configuration, and restart it against the existing version-1 checkpoint. At-least-once semantics mean a bounded replay is safer than manually advancing state.

Do not move or recreate a published tag. If a release is defective, mark it accordingly and publish a new patch version.
