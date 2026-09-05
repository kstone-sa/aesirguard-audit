# Changelog

All notable changes will be documented in this file. The project has not yet published a stable release.

## Unreleased

### Added

- Stable canonical event schema v1.0 and a machine-readable JSON Schema.
- Persistent low-latency file following with bounded event assembly.
- At-least-once checkpoint recovery across retained uncompressed rotations.
- Synchronous stdout and append-only managed-file sinks.
- SIEM-agnostic security-event classification and optional analyst-readable rendering.
- CIS Server Level 1 and Level 2 semantic coverage fixtures for the documented distribution matrix.
- Secure filesystem boundaries, structured operational diagnostics, fuzzing, fault injection, and stress tests.
- Reproducible Linux amd64 and arm64 standalone and systemd release packages.

### Release gates

- Empirical validation against controlled real RAW and ENRICHED Audit output on the documented distribution matrix remains pending.
- The repository remains private and no v1.0 tag has been created pending explicit maintainer approval.
