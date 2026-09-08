# Architecture

## Scope

AesirGuard Audit converts Linux Audit streams into canonical newline-delimited JSON. The core understands Linux Audit semantics but does not understand Splunk CIM, Sentinel ASIM, Elastic ECS, or any other backend schema.

The implementation combines strict operational configuration and a structured health surface with the versioned checkpoint and rotation model.

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

Without a checkpoint, the follower opens at offset zero. With `--checkpoint-file`, it locates the device and inode at the current path or among retained uncompressed siblings, validates a complete-line offset, and drains later generations in descending numeric suffix order (`.2` before `.1`, then the active file). During live rename/create rotation it remains attached to the old inode until EOF is stable for the configured drain interval, then switches to the replacement. The assembler is not reset, and a physical partial line can span the transition.

A file descriptor remains attached to its inode after rename. On rotation, the collector drains the old descriptor before opening the new file and preserves the assembler across the transition.

### Record parser

Converts one physical Audit line into a record without requiring libaudit or libauparse. It must preserve repeated and nested fields, distinguish malformed data from unsupported data, and retain enough source information for recovery and diagnostics.

### Event assembler

Groups records by audit ID. Linux Audit records may be interleaved and may arrive out of order.

Completion may be established by:

- an EOE record;
- a PROCTITLE record for an already pending correlation key;
- a known single-record message type;
- a valid event-time watermark.

`PROCTITLE` is the final data record under the Linux Audit completion grammar.
It completes only its own `(node presence, node value, audit ID)` group; physical
record contiguity is never required. An orphan PROCTITLE remains pending, and
a trailing orphan EOE carries no data and emits nothing. PROCTITLE also supplies
an `argv` fallback when `EXECVE` is absent. Inactivity, EOF and shutdown flush
unresolved groups as incomplete; see [Reliability](reliability.md#event-completion-and-latency).

The assembler must use bounded state and report incomplete events explicitly.

### Normalizer and classifier

Decodes supported Linux-specific values and produces a stable canonical event. Current examples include named syscalls from ENRICHED records, numeric syscall and architecture fallbacks for RAW records, results, file capabilities, identities, mandatory access-control evidence, and event-family classification.

The canonical model is SIEM-agnostic. A local audit rule key is preserved as metadata and must not become the portable event type.

### Human renderer

Optionally derives a deterministic analyst-readable message from normalized fields. Renderer version 5 covers the targeted CIS Linux Audit families and the explicitly mapped security-event families. Distribution-specific behavior remains subject to empirical validation. The message is not authoritative, must not replace structured fields, and may be disabled to minimize output volume.

Security conclusions such as privilege escalation or credential theft belong to backend detections, not to this renderer.

### Sinks

The stdout sink writes one event per line and blocks naturally when the consumer applies back-pressure.

The file sink appends NDJSON directly without a userspace queue. Optional per-event sync provides a local durability boundary. Before each write or checkpoint commit, the sink compares its descriptor with the configured path and reopens after rename-based output rotation.

Diagnostics never share the event stream and are written to stderr.

### Operations

The command loads versioned JSON configuration before applying CLI overrides. The main collection loop owns operational counters and emits structured lifecycle, recovery, failure, rotation, and heartbeat records on stderr. This keeps telemetry ordered with collector state and makes a blocked loop externally visible as a missed heartbeat.

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

Downstream adapters may launch AesirGuard Audit and map its fields to their backend schemas. Those adapters and mappings are maintained independently of this repository.

## Back-pressure and buffering

The pipeline must remain bounded. A blocked sink must slow the collector instead of creating an unbounded in-memory queue. The retained Audit files are the primary recovery source, so operational monitoring must detect when consumer lag approaches source-retention limits.

See `reliability.md` for delivery, checkpoint, and rotation guarantees.
