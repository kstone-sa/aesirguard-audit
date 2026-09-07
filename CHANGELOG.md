# Changelog

All notable changes will be documented in this file. The project has not yet published a stable release.

## Unreleased — v0.9.1 correction line

- Support confirmed kernel LOGIN attribution transitions separately from USER_LOGIN,
  retaining correlated syscall context, old/new loginuid/session evidence and source result.
- Support USER_CMD with literal command text, explicit provenance, safe decoding,
  standalone completion and renderer wording scoped to the recorded operation.
- Omit the Audit null rule-key sentinel; preserve real and multi-key handling.
- Omit routine unset login identities without emitting sentinel issues; retain
  explicit LOGIN transition states and exceptional evidence.
- Disable rendered messages in the shipped example for volume-sensitive ingestion;
  explicit CLI/configuration opt-in and renderer/schema semantics remain unchanged.
- Default operational heartbeats to 10m; configuration, CLI overrides and 0s disable remain supported.
- Correct stale renderer references and record the initial Ubuntu 24.04.4 arm64
  ENRICHED exercise without claiming complete distribution qualification.
- Event schema 1.0 and checkpoint schema 2 remain unchanged. Published v0.9.0
  tags and assets are immutable; no new release is published by these changes.

## Unreleased

No entries yet.

## v0.9.0 - 2026-09-07

### Added

- Stable canonical event schema v1.0 and a machine-readable JSON Schema.
- Persistent low-latency file following with bounded event assembly.
- At-least-once checkpoint recovery across retained uncompressed rotations.
- Synchronous stdout and append-only managed-file sinks.
- SIEM-agnostic security-event classification and optional analyst-readable rendering.
- CIS Server Level 1 and Level 2 semantic coverage fixtures for the documented distribution matrix.
- Secure filesystem boundaries, structured operational diagnostics, fuzzing, fault injection, and stress tests.
- Reproducible Linux amd64 and arm64 standalone and systemd release packages.

### Pre-1.0 correctness corrections

- Checkpoint v2 binds safe offsets to bounded content anchors; legacy v1 state requires explicit replay rather than automatic migration.
- Preserve malformed userspace payload evidence, isolate Audit nodes during correlation, and reject special follow sources without blocking.
- Neutralize unsupported mutation claims and conflicting singleton evidence; decode multi-key separators and exclude invalid serials from watermarks.
- Event schema remains v1.0 with existing issue fields; renderer version 5 adds neutral activity wording. Audit node now supplies the default source host while explicit configuration can override it.

### Release status

- v0.9.0 is the first public pre-release and qualification build; it is not a stable compatibility certification.
- Empirical validation against controlled real RAW and ENRICHED Audit output on the documented distribution matrix remains pending before v1.0.
- No stable v1.0 tag has been created.
