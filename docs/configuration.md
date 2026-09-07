# Configuration

audit2json uses one strict, versioned JSON configuration file. Unknown fields, trailing JSON values, unsupported versions, invalid durations, path conflicts, and unsafe option combinations cause startup to fail.

## Loading and validation

```bash
audit2json --config /etc/audit2json/config.json
audit2json --config /etc/audit2json/config.json --check-config
```

`--check-config` performs both structural and semantic validation, writes a `configuration_valid` diagnostic to stderr, and exits without opening the input or sink. It requires `--config`.

Command-line options override values loaded from the file. This includes explicit Boolean overrides such as `--render-message=false`. A positional input path overrides `input.path`.

The configuration must be a regular file, not a symbolic link. Its owner must be root or the effective service user. Its complete directory hierarchy is opened component by component without following symbolic links; every directory must have a trusted owner and must not be group- or world-writable, except for a root-owned sticky directory such as `/tmp`. The file itself may not be group- or world-writable. These checks prevent a privileged collector from consuming configuration replaced by another account.

## Schema version 1

See `configs/audit2json.example.json` for a complete example.

| JSON field | CLI override | Meaning |
|---|---|---|
| `input.path` | positional path | Audit log path |
| `input.follow` | `--follow` | persistent file-follow mode |
| `input.source_host` | `--source-host` | optional canonical source host |
| `input.lock_file` | `--lock-file` | singleton lock path |
| `sink.file` | `--output-file` | managed append-only sink; empty selects stdout |
| `sink.sync` | `--sync-output` | sync every managed-file event |
| `checkpoint.file` | `--checkpoint-file` | durable checkpoint path |
| `checkpoint.interval` | `--checkpoint-interval` | maximum checkpoint interval |
| `collection.poll_interval` | `--poll-interval` | EOF poll interval |
| `collection.event_timeout` | `--event-timeout` | unresolved event inactivity timeout |
| `collection.rotation_drain_interval` | `--rotation-drain-interval` | stable EOF time before generation switch |
| `collection.max_line_bytes` | `--max-line-bytes` | physical line limit |
| `collection.max_pending_events` | `--max-pending-events` | unresolved event limit |
| `collection.max_records_per_event` | `--max-records-per-event` | per-event record limit |
| `collection.max_pending_bytes` | `--max-pending-bytes` | unresolved source-byte limit |
| `mapping.render_message` | `--render-message` | optional convenience/debug renderer; default `false` |
| `operations.heartbeat_interval` | `--heartbeat-interval` | heartbeat period; default `10m`; `0s` disables it |

Durations use Go duration syntax, for example `200ms`, `2s`, or `1m30s`. Zero-valued integer limits mean "use the built-in default"; negative values are invalid.

Rendered messages should normally remain disabled for volume-sensitive SIEM ingestion: they add indexed volume and duplicate canonical fields. The shipped example sets `mapping.render_message` to `false`. Use `--render-message` or configure `mapping.render_message: true` for an explicit convenience/debug opt-in. `message` and `renderer_version` remain supported with their existing semantics.

Configuration reload is deliberately not implemented. A validated restart makes configuration changes explicit and preserves the existing checkpoint and singleton model.

## Compatibility and migration

Schema version 1 is the only configuration version released so far, so there is no historical transformation to perform. The process never rewrites its configuration automatically. Before an upgrade, validate a candidate file with the candidate binary and retain the previous binary and configuration for rollback.

Future schema changes must provide an explicit, documented migration path. Unknown older or newer versions continue to fail closed rather than being interpreted approximately.
