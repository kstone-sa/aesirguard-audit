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

## Implementation status

Milestone v0.4 implements bounded single-generation following, complete-line handling, synchronous sinks, graceful shutdown, and singleton locking. It does not yet persist checkpoints or follow input rotation. Consequently, restart recovery and cross-generation losslessness described below remain target behavior until v0.5 and v0.6 are complete.

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

A small durable cache of recently emitted event identities may reduce replay duplicates, but it does not create exactly-once delivery.

## Checkpoint persistence

Checkpoint updates use:

1. a temporary file in the checkpoint directory;
2. restrictive permissions;
3. complete serialization;
4. file sync;
5. atomic rename;
6. directory sync where supported.

Updates are batched by a configurable time or progress interval. Per-event sync is not required and may conflict with throughput goals.

A corrupted or unsupported checkpoint causes an explicit startup error or a configured recovery action. It never causes an implicit jump to the current EOF.

## Startup recovery

On startup:

1. acquire the per-input singleton lock;
2. read and validate the checkpoint;
3. locate the checkpoint device and inode;
4. seek to the safe offset;
5. drain that generation;
6. continue through newer retained generations;
7. switch to the current input path.

The collector searches current and rotated files for the checkpoint inode. If it cannot locate the inode, it reports a recovery gap and follows the configured fail-closed or operator-approved recovery policy.

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

For truncation on the same inode, detect that file size is smaller than the current offset, report the condition, and restart from the beginning according to the configured recovery policy.

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
- Crashes and forced termination release the lock automatically.

The external scheduler or service manager is responsible for launching and relaunching the process. A singleton lock does not detect a live but hung owner. Heartbeat-based health monitoring belongs to operational supervision and must not kill a process based only on an old PID file.

## Back-pressure

Sinks are synchronous and bounded. When stdout or file output blocks, the collector slows or stops reading. No unbounded in-memory output queue is introduced.

The Audit files then become the recovery buffer. Operational telemetry must expose consumer lag and warn before retained rotated files can be deleted.

## File sink

The managed file sink:

- writes append-only NDJSON;
- makes completed lines visible promptly;
- optionally syncs each accepted event;
- will sync durable output before advancing a durability-dependent input checkpoint;
- will support managed rename-based rotation or an explicit reopen signal;
- never relies on unmanaged shell redirection for long-running rotation.

Input-log rotation and output-file rotation are independent state machines. Managed output rotation and checkpoint coupling are not implemented in v0.4.

## Failure reporting

Parser failures, unsupported records, checkpoint corruption, source gaps, sink failures, truncation, and state-limit violations are reported explicitly.

Diagnostics go to stderr. When safe and bounded, malformed source data is preserved in a structured fallback event so a poison record does not permanently block checkpoint progress.
