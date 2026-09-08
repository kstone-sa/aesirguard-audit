# Public release checklist

This is the authoritative operational gate for public pre-release publication and the later stable v1.0 release. Public source availability and a pre-1.0 release do not replace empirical validation or maintainer approval for v1.0.

## Completed in the v1.0 readiness pass

- [x] Define canonical schema v1.0 and publish a machine-readable JSON Schema; final freeze occurs with the approved stable tag.
- [x] Separate standalone archives from optional systemd deployment bundles.
- [x] Make release archive metadata reproducible from the tagged commit.
- [x] Verify complete package checksums, contents, binary startup, and configuration before release publication.
- [x] Add contribution, security, changelog, compatibility, release, and operations guidance.
- [x] Remove stale development-branch wording and obsolete diagnostic workflow configuration.
- [x] Scan the current tree, pull requests, review comments, commit metadata, and failed workflow logs for credentials, private infrastructure, customer data, and obsolete repository-owner links.
- [x] Keep the Apache-2.0 license and AI-assisted development disclosure visible.

## Mandatory before making the repository public

- [ ] Review current GitHub Actions logs and downloadable artifacts for sensitive data immediately before publication.
- [ ] Verify repository description and topics; leave the homepage empty unless there is a real project site to link.
- [ ] Confirm that README, compatibility, changelog, roadmap, security policy and release documentation clearly identify pre-1.0 releases as pre-release/qualification software and do not claim empirical distribution compatibility.
- [ ] Review the intended `main`/tag protection policy and private security-reporting activation steps. Under the current GitHub plan, these controls may be unavailable while the repository is private; activate and verify them immediately after visibility changes.
- [ ] Obtain explicit maintainer approval to change visibility.

## Mandatory immediately after becoming public

- [ ] Enable GitHub private vulnerability reporting and verify that **Security → Report a vulnerability** is available.
- [ ] Enable enforceable branch protection/rulesets for `main`, require the shared verification status check, disable force-push/delete, and restrict stable-tag creation/update/deletion as supported by the plan.
- [ ] Verify that repository description, topics, license detection and public security/contribution documentation render correctly.

## Before publishing the intended v0.10.0 pre-release

- [ ] Recheck the pinned Go toolchain's support/security status and pass the full shared release gate on the exact approved commit.
- [ ] Create an annotated `v0.10.0` tag only from that approved `main` commit.
- [ ] Verify that the GitHub release is marked **Pre-release** and contains the four expected archives plus `SHA256SUMS`.
- [ ] Download the intended qualification package and `SHA256SUMS` from GitHub and verify the published download independently before live testing.

Published audit2json v0.9.0/v0.9.1 remain immutable historical releases. Further qualification continues under AesirGuard Audit; fixes in pre-1.0 releases do not imply stable compatibility.

- [ ] Finish source rebranding review and the repository rename.
- [ ] Obtain separate maintainer approval before creating v0.10.0.

## Mandatory before stable v1.0.0

- [ ] Complete controlled local testing with real RAW and ENRICHED events for every distribution in `docs/compatibility.md`.
- [ ] Record tested distribution, kernel, auditd, audit rules, and rotation behavior without committing identifying data.
- [ ] Convert confirmed variations into sanitized regression fixtures and rerun the full shared verification suite.
- [ ] Review all public release notes and compatibility claims against the completed empirical matrix.
- [ ] Recheck the pinned Go toolchain's support/security status and pass the full shared release gate on the approved stable commit.
- [ ] Obtain explicit maintainer approval for stable release.
- [ ] Create and verify the annotated `v1.0.0` tag only from the approved `main` commit.

GitHub documents [ruleset availability by plan](https://docs.github.com/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets) and [private reporting for public repositories](https://docs.github.com/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability). Do not treat an unavailable private-repository control as enabled, or require an impossible pre-visibility configuration step.

## Mandatory after stable tagging, before promotion

- [ ] Download the selected package variant and `SHA256SUMS` from the GitHub release and verify the published files independently.

History rewriting, deletion of review records, repository visibility changes, and stable release approval are never implicit parts of this checklist. They require explicit maintainer decisions.
