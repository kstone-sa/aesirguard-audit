# Public release checklist

This is the authoritative operational gate for making the repository public and tagging v1.0. A checked implementation item does not replace empirical validation or maintainer approval.

## Completed in the v1.0 readiness pass

- [x] Define canonical schema v1.0 and publish a machine-readable JSON Schema; final freeze occurs with the approved stable tag.
- [x] Separate standalone archives from optional systemd deployment bundles.
- [x] Make release archive metadata reproducible from the tagged commit.
- [x] Verify complete package checksums, contents, binary startup, and configuration before release publication.
- [x] Add contribution, security, changelog, compatibility, release, and operations guidance.
- [x] Remove stale development-branch wording and obsolete diagnostic workflow configuration.
- [x] Scan the current tree, pull requests, review comments, commit metadata, and failed workflow logs for credentials, private infrastructure, customer data, and obsolete repository-owner links.
- [x] Keep the Apache-2.0 license and AI-assisted development disclosure visible.

## Mandatory before visibility change or v1.0 tag

- [ ] Complete controlled local testing with real RAW and ENRICHED events for every distribution in `docs/compatibility.md`.
- [ ] Record tested distribution, kernel, auditd, audit rules, and rotation behavior without committing identifying data.
- [ ] Convert confirmed variations into sanitized regression fixtures and rerun the full CI suite.
- [ ] Review all remaining GitHub Actions logs and downloadable artifacts for sensitive data immediately before publication.
- [ ] Review the intended `main`/tag protection policy and private security-reporting activation steps. Under the current GitHub plan, these controls may be unavailable while the repository is private; activate and verify them immediately after visibility changes, before tagging.
- [ ] Set the public repository description, topics, and homepage as appropriate.
- [ ] Obtain explicit maintainer approval to change visibility.

## Mandatory after becoming public, before v1.0 tag

- [ ] Enable GitHub private vulnerability reporting and verify that the private report form is available.
- [ ] Enable enforceable branch protection/rulesets for `main`, require the shared verification status check, and restrict stable-tag creation/update/deletion as supported by the plan.
- [ ] Recheck the pinned Go toolchain's support/security status and pass the full shared release gate on the approved commit.
- [ ] Create and verify the annotated v1.0 tag only from the approved `main` commit.

GitHub documents [ruleset availability by plan](https://docs.github.com/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets) and [private reporting for public repositories](https://docs.github.com/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability). Do not treat an unavailable private-repository control as enabled, or require an impossible pre-visibility configuration step. No settings were enabled by this checklist.

## Mandatory after tagging, before promotion

- [ ] Download both package variants and `SHA256SUMS` from the GitHub release and verify the published files independently.

History rewriting, deletion of review records, and repository visibility changes are never implicit parts of this checklist. They require an explicit, separately reviewed maintainer decision.
