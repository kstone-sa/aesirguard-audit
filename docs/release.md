# Release procedure

## Prepare

1. Confirm that CI passes on `main` and that the documented compatibility claims match completed validation.
2. Update release notes and the roadmap without presenting synthetic fixtures as empirical distribution support.
3. Use the exact Go version in `.go-version` and run `scripts/verify-all.sh` as documented below, including the current vulnerability check.
4. Complete every mandatory pre-tag item in `docs/public-release-checklist.md`.
5. Create an annotated semantic-version tag from the reviewed `main` commit.

## Publish

Pushing a tag matching `v*` runs the release workflow. Both main/PR CI and tag verification call the same reusable `verify.yml` workflow and `scripts/verify-all.sh`. Tag publication requires its successful completion; it cannot bypass formatting, full tests, race, vet, schema validation, both fuzz campaigns, benchmark, vulnerability checking, package inspection/fault tests or reproducibility verification. It creates static Linux amd64 and arm64 packages with embedded version metadata:

- the standalone archive contains the binary, example configuration, JSON Schema, license, public project policies, changelog, README, and documentation, with no service-manager files;
- the systemd archive contains the same payload plus the unit, sysusers, and tmpfiles examples.

Verification requires exactly the four expected archives and their four unique checksum entries. Every archive is checked for safe paths, regular files/directories only, normalized timestamps/ownership/modes, exact documentation/schema/configuration assets, correct ELF architecture, static linkage, actual Go build information, exact release identity and `BUILD-INFO.json`. Standalone and systemd variants must contain identical common payloads. Native-architecture binaries in both variants run `--version` and configuration validation. On the amd64 runner, arm64 is statically inspected, **not executed**.

Ten package fault tests reject missing assets, wrong architecture, dynamic linkage, wrong identity, variant drift, symlinks, traversal and checksum omissions/duplicates/corruption. Rebuilding under restrictive source permissions and umask must produce identical checksums. Reproducibility is scoped to identical source, pinned toolchain and normalized build inputs; it is not a claim that arbitrary toolchains or runner images produce identical bytes.

All GitHub Actions are pinned to immutable commit SHAs. Verification has read-only repository permissions and checkout does not persist credentials. The separate publication job has `contents: write`, downloads only the verified artifact from that workflow run, rechecks checksums and publishes it without executing repository code. Repository/tag rules and maintainer approval remain necessary: an actor allowed to edit workflows or create arbitrary tags can change the policy itself.

## Local release gate

Install the Go version from `.go-version`, Python `jsonschema==4.26.0` in an isolated environment, and development-only `govulncheck`:

```bash
go install golang.org/x/vuln/cmd/govulncheck@v1.7.0
./scripts/verify-all.sh candidate "$(git rev-parse HEAD)" "$(git show -s --format=%ct HEAD)" /tmp/audit2json-candidate
```

Ensure the installed tools are on PATH; the output directory must be absent or empty. To inspect existing packages against the same source checkout:

```bash
./scripts/verify-release.sh /tmp/audit2json-candidate candidate "$(git rev-parse HEAD)" "$(git show -s --format=%ct HEAD)"
```

The vulnerability database is current at execution time, so a newly published advisory can deliberately fail a previously passing source revision. This does not change package bytes. Keep the tool and Go pins under review; a passing check is not proof of absence of vulnerabilities.

After publication, download the selected archive and `SHA256SUMS` from GitHub and verify them again before promoting the release. This final check covers the published download path in addition to the workflow's pre-publication verification.

## Roll back

Retain at least the previous release archive and configuration. Stop the collector cleanly, restore the previous binary, validate its configuration, and restart it against the existing version-1 checkpoint. At-least-once semantics mean a bounded replay is safer than manually advancing state.

Do not move or recreate a published tag. If a release is defective, mark it accordingly and publish a new patch version.
