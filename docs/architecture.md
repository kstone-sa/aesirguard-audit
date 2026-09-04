# Architecture

## Scope

audit2json converts Linux Audit streams into canonical newline-delimited JSON. The core understands Linux Audit semantics but does not understand Splunk CIM, Sentinel ASIM, Elastic ECS, or any other backend schema.

The milestone v0.3 branch is a batch converter with one canonical schema, CIS-oriented semantic classification, and deterministic rendering for the supported CIS Linux Audit families. This document describes the target persistent architecture; planned collector components must not be treated as implemented.

## Target data flow

```text
audit.log or stdin
        |
        v
collector and line reader
        |
        v
record lexer and parser
        |
        v
event assembler
        |
        v
normalizer and classifier
        |
        +----> optional human renderer
        |
        v
stdout or append-only file sink
```

Each stage has one responsibility and can be tested independently.

## Components

### Collector

Owns file descriptors, polling, partial lines, EOF waiting, checkpoints, and input rotation. It does not parse Audit fields.

A file descriptor remains attached to its inode after rename. On rotation, the collector drains the old descriptor before opening the new file and preserves the assembler across the transition.

### Record parser

Converts one physical Audit line into a record without requiring libaudit or libauparse. It must preserve repeated and nested fields, distinguish malformed data from unsupported data, and retain enough source information for recovery and diagnostics.

### Event assembler

Groups records by audit ID. Linux Audit records may be interleaved and may arrive out of order.

Completion may be established by:

- an EOE record;
- a terminal record such as PROCTITLE;
- a known single-record message type;
- an event-time watermark;
- an inactivity timeout.

The assembler must use bounded state and report incomplete events explicitly.

### Normalizer and classifier

Decodes Linux-specific values and produces a stable canonical event. Examples include architecture, syscall, errno, result, permissions, capabilities, socket families, and event-family classification.

The canonical model is SIEM-agnostic. A local audit rule key is preserved as metadata and must not become the portable event type.

### Human renderer

Optionally derives a deterministic analyst-readable message from normalized fields. Renderer version 2 covers the supported CIS Linux Audit families. The message is not authoritative, must not replace structured fields, and may be disabled to minimize output volume.

Security conclusions such as privilege escalation or credential theft belong to backend detections, not to this renderer.

### Sinks

The stdout sink writes one event per line and blocks naturally when the consumer applies back-pressure.

The file sink appends NDJSON durably for agents that monitor files. Output-file rotation and durability are separate from input-log rotation.

Diagnostics never share the event stream and are written to stderr.

## Process model

The target process is long-running. A non-blocking advisory lock prevents two instances from reading the same input and checkpoint concurrently. The lock is scoped per input instance, not globally.

If another process owns the lock, a newly scheduled invocation exits successfully without emitting events. Kernel-managed advisory locking is authoritative; PID metadata is diagnostic only.

An external scheduler or supervisor starts and restarts the process. Checkpointing restores progress; it does not restart the process or detect a live but hung process.

## Backend boundary

Backend packages consume canonical NDJSON and own:

- source and sourcetype configuration;
- event-time extraction;
- backend field aliases;
- data-model mappings;
- tags, dashboards, and detections;
- transport acknowledgements beyond the selected sink.

A Splunk TA may launch audit2json and map its fields to CIM. Those mappings do not belong in this repository.

## Back-pressure and buffering

The pipeline must remain bounded. A blocked sink must slow the collector instead of creating an unbounded in-memory queue. The retained Audit files are the primary recovery source, so operational monitoring must detect when consumer lag approaches source-retention limits.

See `reliability.md` for delivery, checkpoint, and rotation guarantees.
