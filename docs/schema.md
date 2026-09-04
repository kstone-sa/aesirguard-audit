# Canonical JSON schema

## Status

Canonical schema v0.2 is implemented and emitted by default. The former compact v0.1 output remains available with `--schema v0.1` for controlled migration.

Output is newline-delimited JSON: one logical Audit event per line. Empty optional objects, fields, and arrays are omitted. Fields documented as arrays never change to scalars.

The v0.2 schema is versioned but not yet declared stable. Additive refinement is expected before v1.0.

## Top-level contract

| Field | Type | Meaning |
|---|---|---|
| `schema_version` | string | Canonical schema version; currently `0.2` |
| `audit` | object | Source Audit ID, event time, and serial |
| `source` | object | Optional host and boot identity |
| `event` | object | Record type, completion, result, and integrity metadata |
| `rule` | object | Local Audit rule keys |
| `actor` | object | Source user, group, and session identifiers |
| `process` | object | Process, executable, command, and syscall source values |
| `paths` | array | Ordered PATH records with their associated metadata |
| `unmapped` | array | Per-record fields not represented elsewhere |

The objects remain separate deliberately: a local rule key is not an event type, the actor is not necessarily the effective process identity, and source codes are not normalized names.

## Audit envelope

`audit.id` preserves the original `timestamp:serial` identifier. When valid, it is also split into:

- `audit.time`: UTC RFC 3339 timestamp;
- `audit.serial`: unsigned JSON number.

An invalid identifier is retained in `audit.id`; derived fields are omitted and `event.issues` contains `invalid_audit_id`. Evidence is not discarded because an envelope could not be normalized.

## Source identity

`source.host` is taken from an explicit `--source-host` option when supplied, otherwise from the Audit `node` field. `source.boot_id` is supplied explicitly with `--source-boot-id`.

The Audit ID alone is not globally unique. Consumers that require stable identity across hosts and reboots must provide both host and boot identity. The batch converter does not guess a boot ID for historical files; automatic local source discovery belongs to the persistent collector.

## Event metadata

| Field | Type | Meaning |
|---|---|---|
| `event.type` | string | Deterministic primary Linux Audit record type |
| `event.record_types` | array of strings | Unique physical record types in first-observed order |
| `event.record_count` | number | Number of physical records assembled |
| `event.complete` | boolean | Whether a recognized complete boundary was observed |
| `event.completion` | string | `eoe`, `proctitle`, `single_record`, `watermark`, `timeout`, or `eof` |
| `event.result.raw` | string | Original `success` or `res` value |
| `event.issues` | array | Structured conversion or integrity issues |

`event.type` is source classification, not a portable activity code. Canonical event codes and normalized result values belong to the next normalization milestone.

EOE, PROCTITLE, and known single-record boundaries are currently reported as complete. Watermark, inactivity timeout, and EOF flushes are reported as incomplete so downstream consumers can make an explicit policy decision.

## Rule, actor, and process

`rule.keys` is always an array because an event may carry more than one local Audit rule key.

Actor identifiers remain source strings in v0.2: `auid`, `uid`, `euid`, `gid`, `egid`, and `session`. Account-name resolution is not performed.

The process object may contain:

- `pid`, `ppid`, `executable`, `cwd`, and `tty`;
- `argv`, always an array preserving EXECVE argument boundaries;
- `command`, a deterministic display form derived from `argv` or PROCTITLE;
- `arch_raw` and `syscall_raw`, which deliberately preserve source codes.

The display command is not a shell-escaped reconstruction and must not replace `argv` in analytical logic.

## PATH records

`paths` is always an array of objects, sorted by numeric `item` where present and then by source order. Each object keeps the association between:

- `item`;
- `name` and `name_type`;
- `inode` and `device`;
- `mode`;
- `ouid` and `ogid`.

No scalar-versus-array switch occurs when an event contains one path.

## Loss-aware fallback

`unmapped` contains one object for each physical record that still has fields not represented by v0.2. Each object has a record `type` and a `fields` map. Every map value is an array of strings, even when only one value exists.

This preserves repeated and nested fields without forcing unsupported record families into an incorrect model. Envelope fields and values already represented canonically are omitted. Some raw EXECVE fields are intentionally retained because their quoting and encoding semantics may differ from the derived `argv`.

## Example

A process event has this shape:

```json
{
  "schema_version": "0.2",
  "audit": {
    "id": "1721721600.123:42",
    "time": "2024-07-23T08:00:00.123Z",
    "serial": 42
  },
  "source": {
    "host": "workstation-01",
    "boot_id": "8b9c..."
  },
  "event": {
    "type": "SYSCALL",
    "record_types": ["SYSCALL", "EXECVE", "PATH", "EOE"],
    "record_count": 4,
    "complete": true,
    "completion": "eoe",
    "result": {"raw": "yes"}
  },
  "rule": {"keys": ["privileged"]},
  "process": {
    "pid": "200",
    "executable": "/usr/bin/sudo",
    "argv": ["sudo", "cat", "/etc/shadow"],
    "arch_raw": "c000003e",
    "syscall_raw": "59"
  },
  "paths": [
    {"item": 0, "name": "/etc/shadow", "name_type": "NORMAL"}
  ]
}
```

The golden fixture in `testdata/execve.v0.2.json` documents a complete emitted event.

## v0.1 compatibility

Use `--schema v0.1` to emit the former compact fields: `id`, `key`, `type`, `res`, identity strings, process fields, and scalar-or-array path output.

This mode exists for migration only. New integrations should consume v0.2 and branch on `schema_version`.

## Future normalization and rendering

The next milestone may add normalized architecture, syscall, errno, permissions, capabilities, socket-family values, deterministic event codes, mapping versions, and an optional analyst-readable message.

Normalized values will be added alongside source evidence. Splunk CIM, Sentinel ASIM, Elastic ECS, aliases, tags, detections, and risk classifications remain backend responsibilities.
