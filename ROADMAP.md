# Roadmap

## Project principles

- Native Go and standard library only.
- No Python, CGO, libaudit, libauparse, or external runtime.
- SIEM-agnostic canonical NDJSON.
- Low latency, bounded memory, and natural back-pressure.
- Lossless processing while retained source data is available.
- At-least-once recovery with minimal, bounded duplication.
- Correctness before optimization.

Milestones may be developed separately, but persistent collection is not production-ready until following, checkpoint recovery, and rotation handling work together.

## v0.1 - Parser foundation

**Status: implemented as a prototype**

Implemented:

- basic Audit record parsing;
- grouping by audit ID;
- basic EXECVE reconstruction;
- PROCTITLE decoding;
- PATH name collection;
- compact NDJSON output.

Known gaps:

- incomplete Audit grammar coverage;
- incomplete event-boundary handling;
- destructive loss of fields needed for later normalization;
- synthetic happy-path test coverage only;
- nondeterministic flush order for incomplete events.

## v0.2 - Parser correctness, canonical schema, and renderer

**Status: implemented**

Parser correctness, deterministic event assembly, the security-oriented canonical schema, ENRICHED identity handling, and the optional process renderer are implemented. Multi-distribution CIS coverage is delivered by v0.3.

Goal: make record parsing and event assembly safe enough to support persistent collection.

Deliverables:

- preserve the audit ID when records contain nested or repeated fields;
- robust quoted, escaped, hexadecimal, and malformed-value handling;
- explicit event time, serial, source identity, and completion state;
- stable field types;
- deterministic ordering;
- EOE, known single-record, watermark, and timeout boundaries;
- interleaved and out-of-order record handling;
- explicit issues for unsupported record families without copying arbitrary fields;
- optional deterministic human-readable process messages;
- golden tests using representative Linux Audit samples.

## v0.3 - Extended normalization and CIS event families

**Status: implemented for the scoped CIS semantic families**

Goal: translate Linux Audit semantics without introducing backend-specific schemas. Initial guaranteed coverage targets CIS Server Level 1 and Level 2 Audit event families across Debian 12/13, Ubuntu 22.04/24.04, RHEL 8/9, and Oracle Linux 8/9.

Deliverables:

- ENRICHED syscall names with architecture-dependent RAW fallback fields;
- result normalization;
- semantic file-capability decoding;
- record-family classifiers for process, authentication, file, policy, and network activity;
- stable canonical event codes;
- deterministic human-readable templates for every supported CIS Audit family;
- a versioned CIS coverage matrix and representative multi-distribution fixtures;
- raw and normalized values kept distinct where interpretation may vary;

Broader architecture tables, errno, permission, signal, socket-family, and message-type normalization are deferred until driven by the real corpus in v0.8. The schema version identifies the current contract; separate mapping-version metadata is not yet emitted.

Splunk CIM, Sentinel ASIM, Elastic ECS, detections, and risk classifications remain backend responsibilities.

## v0.4 - Persistent collector and sinks

**Status: implemented**

Goal: run continuously with low latency.

Deliverables:

- direct file-follow mode;
- configurable polling;
- EOF waiting;
- partial-line preservation;
- bounded event state;
- graceful shutdown;
- synchronous stdout sink with natural back-pressure;
- append-only file sink;
- non-blocking per-input singleton lock;
- clean success exit when another healthy instance owns the lock.

These deliverables are implemented for one open file generation.

## v0.5 - Checkpoint and crash recovery

**Status: implemented**

Deliverables:

- versioned checkpoint format;
- device, inode, and safe input offset;
- atomic same-directory temporary write, fsync, and rename;
- checkpoint only after complete-line processing and successful sink write;
- safe offset that does not pass the oldest unresolved event;
- configurable checkpoint interval;
- restart from the durable checkpoint;
- bounded replay window and optional recent-event identity cache;
- corrupted-checkpoint detection and explicit recovery policy.

Delivery semantics are at-least-once. Exact end-to-end indexing cannot be promised by an unacknowledged stdout sink.

The durable format, safe-offset invariant, sink/checkpoint ordering, configurable interval, and same-generation resume are implemented.

## v0.6 - Input and output rotation

**Status: implemented**

Deliverables:

- device and inode tracking;
- rename/create detection;
- drain the old descriptor before switching;
- preserve pending events across file generations;
- locate the checkpoint inode among retained rotated files after restart;
- detect truncation;
- explicit gap reporting when the checkpoint generation is no longer available;
- managed rotation or reopen support for the file sink;
- stress tests for rapid rotation and partial multi-record events.

Rename-based rotation is required for the strongest lossless guarantee. Copytruncate support is best effort.

The implementation includes retained uncompressed generation discovery, live rename/create drain and switch, cross-generation pending state, explicit fail-closed truncation detection, managed output reopen, and focused rotation tests. Automatic continuation after copytruncate is not presented as lossless and remains disabled.

## v0.7 - Configuration and operations

**Status: implemented**

Deliverables:

- validated JSON configuration;
- command-line overrides for bootstrap and diagnostics;
- input, sink, checkpoint, polling, timeout, and mapping settings;
- signal handling;
- structured operational diagnostics on stderr;
- counters for input lag, pending events, parse failures, replay, gaps, and rotations;
- health and heartbeat information for external supervision.

Configuration schema version 1 is strict and supports CLI overrides. Operational records are JSON on stderr and include lifecycle, recovery, rotation, failure, process-lifetime counters, instantaneous lag and pending-state gauges, and a configurable heartbeat.

## v0.8 - Performance and regression

**Status: 8A and 8C implemented; 8B pending empirical corpus**

### v0.8A - Synthetic hardening

Implemented:

- bounded fuzz campaigns for the record parser and assembler state transitions;
- generated interleaved and out-of-order multi-record events with conservation and determinism assertions;
- large fragmented EXECVE reconstruction;
- sink failure and checkpoint commit-order fault injection;
- slow-consumer back-pressure tests;
- rapid rotation, missing generation, truncation, partial-line, and many-generation recovery stress tests;
- an allocation-aware end-to-end parsing, assembly, normalization, rendering, and JSON benchmark;
- race-detector validation.

### v0.8B - Empirical distribution validation

Pending:

- capture and sanitize real RAW and ENRICHED Audit output;
- validate CIS Server Level 1 and Level 2 families on Debian 12/13, Ubuntu 22.04/24.04, RHEL 8/9, and Oracle Linux 8/9;
- convert confirmed distro differences and previously unseen record shapes into regression fixtures;
- document the tested auditd, kernel, and distribution versions.

### v0.8C - Security event coverage

Implemented:

- parse nested user-space Audit payloads and structured AVC decision prose;
- classify authentication, account, session, system, service, audit-daemon, MAC, kernel-security, anomaly, and integrity families independently from CIS;
- emit typed target, origin, and access-control evidence without copying arbitrary Audit fields;
- render every mapped action with deterministic versioned templates;
- keep potentially compound kernel records open until `EOE` or the configured assembler boundary while completing known standalone user-space records immediately.

Deliverables:

- events/sec and MB/sec benchmarks;
- allocation, memory, and CPU profiles;
- fuzz tests;
- real multi-distribution corpus;
- malformed and oversized records;
- large and fragmented EXECVE events;
- checkpoint and rotation fault injection;
- slow-consumer and back-pressure tests.

Optimize only after correctness and measurement.

### Validation tracks and release gates

- 8A: synthetic hardening is implemented, including exact record-conservation fuzz assertions.
- 8B: empirical validation on the supported distribution matrix remains pending and may take additional time.
- 8C: broader security-event normalization and rendering is implemented independently from the CIS rule profile.

Development toward v0.9 and v1.0 may proceed while 8B remains open. Until 8B is complete, documentation and release notes must clearly distinguish synthetic coverage from empirically verified distribution support, and stable-release support claims must remain limited accordingly.

## v0.9 - Production hardening

**Status: implemented**

Implemented:

- explicit version-1 configuration and checkpoint compatibility policy, with fail-closed handling for unsupported versions;
- interrupted checkpoint replacement and crash-window tests;
- symlink, ownership, writable-path, and regular-file checks at configuration and managed-output boundaries;
- restrictive managed-file creation and a hardened example systemd service;
- embedded build version reporting and tagged static Linux amd64/arm64 release archives with checksums;
- operational installation, monitoring, recovery, upgrade, release, and rollback procedures;
- an honest compatibility matrix that keeps empirical distro validation in milestone 8B.

## v1.0 - Stable release

**Status: implementation complete; release blocked on empirical milestone 8B and final maintainer approval**

Requirements:

- documented stable canonical schema;
- all regression and fault-injection tests passing;
- checkpoint and rotation guarantees verified;
- bounded resource use under sustained load;
- production packaging and operating guidance;
- no backend-specific data model in the core.

Implemented release preparation includes the frozen canonical v1 contract and JSON Schema, reproducible standalone and systemd packages, open-source contribution and security policies, and a public-release audit checklist. No v1.0 tag or stable distribution-support claim is made until the remaining gate is complete.

### Public release preparation

Before changing repository visibility to public:

- consolidate the README around installation, runtime modes, delivery semantics, limitations, and verified support;
- keep `AGENTS.md` concise and development-focused;
- remove obsolete examples, stale roadmap language, and redundant planning notes;
- add or verify `CONTRIBUTING.md`, `SECURITY.md`, changelog/release notes, and reproducible release builds;
- review the entire Git history, issues, pull requests, workflow logs, artifacts, fixtures, and documentation for credentials, internal names, private infrastructure, customer data, and unsanitized audit records;
- sanitize or remove sensitive material before publication;
- require explicit maintainer approval before any history rewrite or repository visibility change.

The tracked execution state for these checks is maintained in `docs/public-release-checklist.md`; this roadmap records policy rather than a second checklist.
