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
- `replay_candidates`: events emitted between checkpoint resume and catching the live tail;
- `gaps`: detected missing or truncated source generations;
- `rotations`: completed input-generation switches.

`replay_candidates` is intentionally conservative. It describes events that may duplicate downstream data after recovery; stdout provides no acknowledgement that would let audit2json know whether a SIEM indexed an earlier copy.

The instantaneous gauges are `input_lag_bytes`, `pending_events`, and `pending_bytes`. Lag includes unread bytes visible in the active and later retained generations and is omitted when a stable estimate is temporarily unavailable.

External supervision should alert on missed heartbeats, non-zero gaps, sustained or retention-threatening lag, parse failures, and repeated restarts. It should not parse human prose or mix stderr into the event stream.
