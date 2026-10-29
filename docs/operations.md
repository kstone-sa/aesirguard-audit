# Operations and health

Operational diagnostics are newline-delimited JSON on stderr. Canonical Audit events remain isolated on stdout or in the configured managed file sink.

Every diagnostic contains `timestamp` (UTC RFC 3339), `level` (`info`, `warn`, or `error`), and a stable `event` name.

The collector reports lifecycle, configuration validation, singleton contention, recovery, rotation, parse failure, source gap, and fatal events. Errors returned from the command are also emitted as a final `fatal` record by the executable.

## Heartbeat

Follow mode emits `heartbeat` at `operations.heartbeat_interval`, default `10m`. Set the interval to `0s` to disable it. At 2,000 hosts, `10m` produces about 288,000 heartbeats/day, compared with 5.76 million at `30s`; choose an explicit interval to match supervision and ingestion-volume needs. This cadence does not change event, checkpoint, or rotation timing. Heartbeats are produced by the main collection loop, so an absent heartbeat can indicate a blocked sink or a stalled collector as well as a dead process.

```json
{"timestamp":"2026-09-04T18:00:00Z","level":"info","event":"heartbeat","health":"ok","uptime_seconds":120,"input_lag_bytes":0,"pending_events":0,"pending_bytes":0,"counters":{"input_lines":1532,"input_bytes":388421,"emitted_events":409,"parse_failures":0,"replay_candidates":0,"gaps":0,"rotations":1}}
```

Counters are process-lifetime monotonic values:

- `input_lines` and `input_bytes`: complete physical Audit input consumed;
- `emitted_events`: canonical events accepted by the sink;
- `parse_failures`: physical records rejected by the parser;
- `assembler_limits`: isolated assembler admission failures;
- `line_limits`: physical lines emitted with a retained prefix and omitted-byte count;
- `replay_candidates`: events emitted between checkpoint resume and catching the live tail;
- `gaps`: detected missing or truncated source generations;
- `rotations`: completed input-generation switches.

`replay_candidates` is intentionally conservative. It describes events that may duplicate downstream data after recovery; stdout provides no acknowledgement that would let AesirGuard Audit know whether a SIEM indexed an earlier copy.

The instantaneous gauges are `input_lag_bytes`, `pending_events`, and `pending_bytes`. Lag includes unread bytes visible in the active and later retained generations and is omitted when a stable estimate is temporarily unavailable.

External supervision should alert on missed heartbeats, non-zero gaps, sustained or retention-threatening lag, parse failures, and repeated restarts. It should not parse human prose or mix stderr into the event stream.

## Compact event output

Keep `mapping.render_message` disabled for volume-sensitive SIEM ingestion.
Rendered messages are optional convenience/debug output that duplicates canonical
information; opt in with `--render-message` or configuration only when useful.
Routine unset login/session attribution adds no issue entries. LOGIN transitions
retain explicit old/new unset semantics, and exceptional evidence still carries
its existing issues. This compaction changes neither event delivery nor checkpoints.

## Integrity incidents and limit diagnostics

`assembler_limit_exceeded` is an error-level JSON diagnostic, followed by continued
collection. It carries `audit_id`, `node_present` and (when present) `node`,
`limit_name` (`max_records_per_event`, `max_pending_events`, `max_pending_bytes`),
`configured_limit`, `observed_records` including the trigger, `count_complete=false`,
source position, rejection-table gauges and `conservative_isolation`. It contains
no raw Audit payload. For a configured record limit of 256 the first violation
reports 257 physical records for that correlation key; unrelated nodes are not
counted. This is an observed partial count, not the final logical event size.
Exceptional physical-record evidence is canonical output, with explicit incomplete
integrity. `physical_line_limit_exceeded` instead reports observed, retained and
omitted byte counts; its retained raw prefix is marked incomplete.

`source_gap` records a durable prepared incident and its decision to replay the
oldest contiguous retained chain. Its `incident` includes prior checkpoint and
resume identity/offset/anchor, number, reason, time and prepared state.
`potential_data_loss=true` and `possible_duplicates=true` are deliberate warnings.
`recovery_resumed_with_gap` confirms the new checkpoint lineage has committed.
A failure to persist evidence or checkpoint state emits `fatal`; it is not recovery.

`source_gap_history` exposes the last durable incident and cumulative count at
startup. After a gap, heartbeats include `persistent_gaps` and
`integrity="source_gap_recorded"` even when process-lifetime `counters.gaps` is zero.
`health="ok"` means collection liveness, not lossless continuity. The ledger retains
eight incidents plus a lifetime count; preserve it with checkpoint backups.
Supervision, including Splunk `_internal` consumers, should alert on these stable
JSON event names and integrity fields, while keeping stderr separate from canonical
Audit output. No backend-specific code or configuration is required by the core.
