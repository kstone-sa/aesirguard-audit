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
- EOE, PROCTITLE, single-record, watermark, and timeout boundaries;
- interleaved and out-of-order record handling;
- explicit issues for unsupported record families without copying arbitrary fields;
- optional deterministic human-readable process messages;
- golden tests using representative Linux Audit samples.

## v0.3 - Extended normalization and CIS event families

**Status: implemented**

Goal: translate Linux Audit semantics without introducing backend-specific schemas. Initial guaranteed coverage targets CIS Server Level 1 and Level 2 Audit event families across Debian 12/13, Ubuntu 22.04/24.04, RHEL 8/9, and Oracle Linux 8/9.

Deliverables:

- architecture and syscall mappings;
- result and errno normalization;
- permissions, capabilities, signals, socket families, and message-type mappings;
- record-family classifiers for process, authentication, file, policy, and network activity;
- stable canonical event codes;
- deterministic human-readable templates for every supported CIS Audit family;
- a versioned CIS coverage matrix and multi-distribution corpus;
- raw and normalized values kept distinct where interpretation may vary;
- mapping version metadata.

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

The development branch implements retained uncompressed generation discovery, live rename/create drain and switch, cross-generation pending state, explicit fail-closed truncation detection, managed output reopen, and focused rotation tests. Automatic continuation after copytruncate is not presented as lossless and remains disabled.

## v0.7 - Configuration and operations

**Status: implemented on the development branch**

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

## v0.9 - Production hardening

Deliverables:

- configuration migration;
- checkpoint migration and crash testing;
- permissions and secure file creation;
- packaging documentation;
- operational runbooks;
- compatibility matrix;
- release and rollback procedure.

## v1.0 - Stable release

Requirements:

- documented stable canonical schema;
- all regression and fault-injection tests passing;
- checkpoint and rotation guarantees verified;
- bounded resource use under sustained load;
- production packaging and operating guidance;
- no backend-specific data model in the core.
