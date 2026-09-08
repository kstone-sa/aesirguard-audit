# Release procedure

## Release channels

Published audit2json v0.9.0 and v0.9.1 remain immutable historical releases. The next intended pre-release is AesirGuard Audit v0.10.0, subject to separate maintainer approval; see [migration](rebranding.md). Tags matching `v0.*` are published as GitHub **Pre-releases** and are intended for controlled evaluation, including empirical distribution testing. They are not stable compatibility certification.

The first stable release will be `v1.0.0` after the empirical validation matrix and stable-release checklist are complete.

## Prepare

1. Confirm that CI passes on `main` and that the documented compatibility claims match completed validation.
2. Update release notes and the roadmap without presenting synthetic fixtures as empirical distribution support.
3. Use the exact Go version in `.go-version` and run `scripts/verify-all.sh` as documented below when performing a local independent gate.
4. Complete the applicable items in `docs/public-release-checklist.md` for either a pre-1.0 release or stable v1.0.
5. Select the reviewed `main` revision that will become the release source. Do not move a published release tag afterward.

## Publish

Do not run publication as part of the rebranding pass. Obtain separate maintainer
authorization after source review and repository renaming. Never
republish v0.9.0 or v0.9.1 with renamed assets.

The preferred publication path does not require a local Git or GitHub CLI installation:

1. Open **Actions → Release → Run workflow** in GitHub.
2. Select the `main` branch.
3. Enter a full semantic version such as `v0.10.0`.
4. Run the workflow and wait for verification to complete.

For a manual run, the workflow accepts only `main` and a full `vMAJOR.MINOR.PATCH` version. It runs the shared verification gate first, retains the verified packages, rechecks the transferred checksums, then creates an annotated tag on the exact verified commit and publishes the GitHub release. Tags matching `v0.*` are automatically marked as GitHub **Pre-releases**. The publication job does not check out or execute repository code.

Pushing an existing `v*` tag remains supported as an alternate maintainer path and uses the same verification and publication logic.

Both main/PR CI and release verification call the same reusable `verify.yml` workflow and `scripts/verify-all.sh`. Publication requires successful completion; it cannot bypass formatting, full tests, race, vet, schema validation, both fuzz campaigns, benchmark, vulnerability checking, package inspection/fault tests or reproducibility verification. It creates static Linux amd64 and arm64 packages with embedded version metadata:

`aesirguard-audit_VERSION_linux_ARCH_VARIANT.tar.gz`, with executable `ag-audit`
and `BUILD-INFO.json` product `AesirGuard Audit`. For example, a separately
authorized v0.10.0 would produce `aesirguard-audit_v0.10.0_linux_amd64_standalone.tar.gz`
and the corresponding arm64/systemd variants.

- the standalone archive contains the binary, example configuration, JSON Schema, license, public project policies, changelog, README, and documentation, with no service-manager files;
- the systemd archive contains the same payload plus the unit, sysusers, and tmpfiles examples.

Verification requires exactly the four expected archives and their four unique checksum entries. Every archive is checked for safe paths, regular files/directories only, normalized timestamps/ownership/modes, exact documentation/schema/configuration assets, correct ELF architecture, static linkage, actual Go build information, exact release identity and `BUILD-INFO.json`. Standalone and systemd variants must contain identical common payloads. Native-architecture binaries in both variants run `--version` and configuration validation. On the amd64 runner, arm64 is statically inspected, **not executed**.

Sixteen package fault tests reject missing assets, wrong architecture, dynamic linkage, wrong identity, variant drift, symlinks, traversal, checksum omissions/duplicates/corruption, old binary/systemd/schema/archive names, wrong schema identity and wrong product metadata. Rebuilding under restrictive source permissions and umask must produce identical checksums. Reproducibility is scoped to identical source, pinned toolchain and normalized build inputs; it is not a claim that arbitrary toolchains or runner images produce identical bytes.

All GitHub Actions are pinned to immutable commit SHAs. Verification has read-only repository permissions and checkout does not persist credentials. The separate publication job has `contents: write`, downloads only the verified artifact from that workflow run, rechecks checksums and publishes it without executing repository code. Repository/tag rules and maintainer approval remain necessary: an actor allowed to edit workflows or create arbitrary tags can change the policy itself.

## Local release gate

Install the Go version from `.go-version`, Python `jsonschema==4.26.0` in an isolated environment, and development-only `govulncheck`:

```bash
go install golang.org/x/vuln/cmd/govulncheck@v1.7.0
./scripts/verify-all.sh candidate "$(git rev-parse HEAD)" "$(git show -s --format=%ct HEAD)" /tmp/aesirguard-audit-candidate
```

Ensure the installed tools are on PATH; the output directory must be absent or empty. To inspect existing packages against the same source checkout:

```bash
./scripts/verify-release.sh /tmp/aesirguard-audit-candidate candidate "$(git rev-parse HEAD)" "$(git show -s --format=%ct HEAD)"
```

The vulnerability database is current at execution time, so a newly published advisory can deliberately fail a previously passing source revision. This does not change package bytes. Keep the tool and Go pins under review; a passing check is not proof of absence of vulnerabilities.

After publication, download the selected archive and `SHA256SUMS` from GitHub and verify them again before qualification or promotion. This final check covers the published download path in addition to the workflow's pre-publication verification.

## Roll back

Retain at least the previous release archive and configuration. Stop the collector cleanly, restore the previous binary, validate its configuration, and restart it only against a checkpoint version it supports. Current binaries require checkpoint v2; v1-only binaries cannot consume it. Follow the explicit replay upgrade/rollback procedure in `runbook.md`; never synthesize an anchor for historical v1 state. At-least-once semantics mean a bounded replay is safer than manually advancing state.

Do not move or recreate a published tag. If a release is defective, mark it accordingly and publish a new patch/pre-release version.
