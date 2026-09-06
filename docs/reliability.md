# Reliability model

## Objectives

The target collector prioritizes:

1. no silent loss;
2. low event latency;
3. bounded memory;
4. at-least-once recovery;
5. minimal and bounded duplication;
6. deterministic failure reporting.

These guarantees apply to audit2json and its selected sink. End-to-end indexing guarantees depend on the backend and its acknowledgement model.

## Delivery semantics

The target delivery model is at-least-once.

A successful stdout write confirms that bytes were accepted by the local pipe. It does not prove that a downstream SIEM has durably queued or indexed the event. Therefore exact end-to-end delivery cannot be promised by the stdout sink.

After a crash, audit2json may replay events after the last durable checkpoint. Stable event identity allows a backend to identify duplicates.

The file sink can provide a stronger local durability boundary by flushing and syncing event data before the input checkpoint advances.

## Lossless scope

No source record is intentionally dropped when all of the following hold:

- the checkpointed file generation is still available;
- rotated files remain available until they are drained;
- the configured sink remains writable;
- rotation uses semantics that preserve written bytes;
- the operating system can read and persist the required state.

A malformed physical line is emitted as a canonical `parse_failure` event containing the original line in `audit.raw`. This exceptional fallback allows the checkpoint to advance without silently discarding input; normal events do not carry raw records.

If a source generation is no longer present, audit2json reports a gap. It must not silently resume from the current file and imply continuity.

Copytruncate rotation cannot provide a strict lossless guarantee because data written between copy and truncate may already be lost by the rotation procedure. It is detected and supported only on a best-effort basis.

## Checkpoint invariants

A checkpoint is versioned and contains at least:

- configured input path;
- device ID;
- inode;
- safe byte offset;
- update timestamp;
- recovery metadata required by the active schema.

The safe offset:

- always points to a complete line boundary;
- never advances before the selected sink accepts the corresponding completed events;
- never advances past the first record of the oldest unresolved event unless pending state is durably persisted.

Audit events can be interleaved. Holding the safe offset behind an incomplete event can cause already-emitted later events to be replayed after a crash. This is acceptable under at-least-once semantics and bounds duplication to the unresolved and checkpoint windows.

The checkpoint may retain recent event identities to reduce replay duplicates, but this does not create exactly-once delivery.

## Checkpoint persistence

Checkpoint updates use:

1. a temporary file in the checkpoint directory;
2. restrictive permissions;
3. complete serialization;
4. file sync;
5. atomic rename;
6. directory sync where supported.

Updates are batched by a configurable time or progress interval. Per-event sync is not required and may conflict with throughput goals.

A corrupted, unsupported, or mismatched checkpoint causes an explicit startup error. It never causes an implicit jump to the current EOF. Recovery policies other than fail-closed remain planned.

Checkpoint schema version 1 is the only durable format released so far. It is not rewritten into a different version implicitly. Interrupted temporary checkpoint files are ignored; the last atomically renamed checkpoint remains authoritative. Upgrade and rollback steps are documented in `runbook.md`.

## Startup recovery

On startup:

1. acquire the per-input singleton lock;
2. read and validate the checkpoint;
3. locate its device and inode at the current path or among uncompressed numeric rotations such as `audit.log.1`;
4. seek to the validated complete-line offset;
5. drain retained generations in descending numeric suffix order (`.2` before `.1`, then the active file);
6. switch to and follow the current input path.

If the checkpoint inode cannot be found, recovery fails closed with an explicit source-gap error. Compressed and non-numeric basename-prefixed files are not treated as input generations. Numeric suffixes establish generation order; modification times never do. Missing intermediate generations, duplicate suffix numbers, and inode aliases fail closed as ambiguous or gapped histories.

## Rotation handling

The collector compares the open descriptor identity with the identity currently referenced by the configured path.

For rename/create rotation:

1. keep the old descriptor open;
2. detect that the path references a new inode;
3. read the old inode until stable EOF;
4. preserve partial lines and pending Audit events;
5. open the new inode at offset zero;
6. continue without resetting the assembler.

This permits a logical Audit event to span file generations.

For truncation on the same inode, the collector detects that file size is smaller than the current offset and fails with an explicit source-gap error. It does not silently restart at zero. A configurable best-effort continuation policy remains future work.

## Event completion and latency

Emit an event immediately when a reliable boundary is observed, including EOE, a known terminal record, or a known single-record type.

For ambiguous events, use:

- an event-time watermark while newer records are arriving;
- a monotonic inactivity timeout when the stream is idle.

This avoids unnecessary delay while reading historical backlog and bounds live-event latency when an explicit terminator is absent.

Pending events, records, and bytes have configured upper bounds. Reaching a bound produces a visible operational error; it never causes silent eviction.

## Singleton and supervision

Each input instance uses a non-blocking advisory lock derived from its input and checkpoint identity.

- The lock owner runs persistently.
- A concurrent invocation that finds a healthy owner exits successfully without event output.
- Kernel lock ownership is authoritative.
- PID and start-time metadata are diagnostic.

Follow mode without a checkpoint is allowed but emits a structured `checkpoint_disabled` warning. A restart then begins again at offset zero of the retained input, so durable recovery requires `--checkpoint-file`.
- Crashes and forced termination release the lock automatically.

The external scheduler or service manager is responsible for launching and relaunching the process. A singleton lock does not detect a live but hung owner. Heartbeat-based health monitoring belongs to operational supervision and must not kill a process based only on an old PID file.

## Back-pressure

Sinks are synchronous and bounded. When stdout or file output blocks, the collector slows or stops reading. No unbounded in-memory output queue is introduced.

The Audit files then become the recovery buffer. Operational telemetry exposes consumer lag so supervision can warn before retained rotated files can be deleted. The gauge may be omitted during a rename/create window where no stable filesystem estimate is available.

## File sink

The managed file sink:

- writes append-only NDJSON;
- makes completed lines visible promptly;
- optionally syncs each accepted event;
- syncs durable output before advancing a durability-dependent input checkpoint;
- automatically reopens after managed rename-based rotation;
- never relies on unmanaged shell redirection for long-running rotation.

The sink opens the complete directory hierarchy with pinned descriptors and refuses symbolic links, non-regular files, untrusted owners, group- or world-writable files, and untrusted writable directories. Root-owned sticky directories are accepted. Newly created output files use mode `0600`; group-readable mode may be applied deliberately after creation when a local forwarding agent requires it.

Input-log rotation and output-file rotation are independent state machines. Checkpoint coupling and managed rename-based output reopen are implemented.

## Failure reporting

Parser failures, unsupported records, checkpoint corruption, source gaps, sink failures, truncation, and state-limit violations are reported explicitly.

Diagnostics go to stderr. When safe and bounded, malformed source data is preserved in a structured fallback event so a poison record does not permanently block checkpoint progress.
