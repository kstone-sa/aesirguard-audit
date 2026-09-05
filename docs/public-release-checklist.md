# Public release checklist

This is the authoritative operational gate for making the repository public and tagging v1.0. A checked implementation item does not replace empirical validation or maintainer approval.

## Completed in the v1.0 readiness pass

- [x] Freeze canonical schema v1.0 and publish a machine-readable JSON Schema.
- [x] Separate standalone archives from optional systemd deployment bundles.
- [x] Make release archive metadata reproducible from the tagged commit.
- [x] Verify complete package checksums, contents, binary startup, and configuration before release publication.
- [x] Add contribution, security, changelog, compatibility, release, and operations guidance.
- [x] Remove stale development-branch wording and obsolete diagnostic workflow configuration.
- [x] Scan the current tree, pull requests, review comments, commit metadata, and failed workflow logs for credentials, private infrastructure, customer data, and obsolete repository-owner links.
- [x] Keep the Apache-2.0 license and AI-assisted development disclosure visible.

## Mandatory before visibility change or v1.0 tag

- [ ] Complete empirical milestone 8B using sanitized real RAW and ENRICHED events for every distribution in `docs/compatibility.md`.
- [ ] Record tested distribution, kernel, auditd, audit rules, and rotation behavior without committing identifying data.
- [ ] Convert confirmed variations into sanitized regression fixtures and rerun the full CI suite.
- [ ] Review all remaining GitHub Actions logs and downloadable artifacts for sensitive data immediately before publication.
- [ ] Enable GitHub private vulnerability reporting and verify branch protection for `main`.
- [ ] Set the public repository description, topics, and homepage as appropriate.
- [ ] Obtain explicit maintainer approval to change visibility.
- [ ] Create and verify the annotated v1.0 tag only from the approved `main` commit.

## Mandatory after tagging, before promotion

- [ ] Download both package variants and `SHA256SUMS` from the GitHub release and verify the published files independently.

History rewriting, deletion of review records, and repository visibility changes are never implicit parts of this checklist. They require an explicit, separately reviewed maintainer decision.
