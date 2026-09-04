# Canonical JSON schema

## Status

Canonical schema v0.2 is implemented and is the only event output. There is no legacy schema mode.

Output is newline-delimited JSON: one logical Linux Audit event per line. Empty optional objects, fields, and arrays are omitted. Fields documented as arrays never change to scalars.

The v0.2 schema is versioned but not yet frozen. Additive refinement is expected before v1.0.

## Security-oriented boundary

The parser retains source records while assembling an event, but the canonical output is not a JSON copy of auditd. It emits fields with defined security or forensic meaning.

Unsupported record families are reported through `event.issues`; arbitrary source fields are not copied into the event. This keeps delivery lossless at event level without treating every auditd implementation detail as indexed security data.

## Top-level contract

| Field | Type | Meaning |
|---|---|---|
| `schema_version` | string | Canonical schema version; currently `0.2` |
| `audit` | object | Original Audit ID and event time |
| `source` | object | Optional explicitly configured source host |
| `event` | object | Event type, outcome, integrity anomalies, and conversion issues |
| `rule` | object | Local Audit rule keys |
| `actor` | object | Login identity |
| `process` | object | Effective process identity and execution data |
| `paths` | array | Ordered file objects with associated metadata |
| `message` | string | Optional deterministic analyst-readable message |
| `renderer_version` | string | Renderer template version, present only with `message` |

A local rule key is never used as a portable event type.

## Audit envelope and source

`audit.id` preserves the original `timestamp:serial` identifier used to correlate the physical records. `audit.time` is its UTC RFC 3339 representation.

An invalid ID remains in `audit.id`; `audit.time` is omitted and `event.issues` reports `invalid_audit_id`.

`source` is omitted by default. `source.host` is emitted only when `--source-host` is supplied; the Audit `node` field is not copied automatically because collecting backends commonly attach source identity themselves. Boot identity belongs to collector and checkpoint state and is not repeated in every event.

## Event metadata

| Field | Type | Meaning |
|---|---|---|
| `event.type` | string | Deterministic primary Linux Audit record type |
| `event.success` | boolean | Normalized source result when recognized |
| `event.integrity` | object | Present only for incomplete events |
| `event.issues` | array | Present only for invalid or unsupported input |

Normal EOE, PROCTITLE, and known single-record completions add no assembly metadata. Timeout, watermark, or EOF flushes produce:

```json
"integrity": {
  "state": "incomplete",
  "reason": "timeout"
}
```

Unknown result values and unsupported record families are reported explicitly without copying their arbitrary fields.

## Identity handling

Audit `log_format=ENRICHED` is strongly recommended. ENRICHED names are preferred because they represent the account resolution performed when auditd wrote the event.

When an interpreted name is unavailable, the raw numeric identifier is emitted in a separate `*_id` field. A numeric value is never placed in a name field.

`actor.user` or `actor.user_id` represents the login identity derived from AUID. Process identities are collapsed:

- effective process identity is omitted when equal to the login identity;
- real process identity is omitted when equal to either login or effective identity;
- differing identities use `process.user` or `process.user_id`, and `process.real_user` or `process.real_user_id`.

SUID, FSUID, SGID, FSGID, and their interpreted forms are not emitted.

## Process data

The process object may contain:

- `pid` and `ppid`, retained for process correlation and tree reconstruction;
- `name`, `executable`, `cwd`, and `tty`;
- `argv`, always an array preserving EXECVE argument boundaries;
- `syscall` when an ENRICHED name is available;
- `syscall_number` and `architecture_code` together as the RAW fallback, because a syscall number is architecture-dependent;
- `return_value`, derived from the Audit `exit` field.

The ENRICHED architecture name is not emitted because it adds no useful context once the syscall is named. No derived command-line string is emitted by default. Backend adapters can derive one from `argv` without paying the indexed-volume cost twice.

## PATH records

`paths` is always an array of objects sorted internally by Audit `item`; the item number itself is not emitted.

A path may contain:

- `name` and `name_type`, with `name_type` retaining the Audit operation role such as `CREATE`, `DELETE`, `PARENT`, or `NORMAL`;
- `owner` and `group` from ENRICHED data;
- `owner_id` and `group_id` only when names are unavailable;
- semantic non-empty file capabilities.

Inode, device, and raw mode values are not emitted. A capability mask is decoded to ordered Linux names in `permitted` or `inheritable`; `effective` is a boolean. Zero masks, capability format and root-ID metadata, and raw hexadecimal masks are omitted. Invalid or unknown capability encodings produce `event.issues` rather than silently disappearing.

## Optional human renderer

`--render-message` adds `message` and `renderer_version` when a supported deterministic template exists.

The renderer:

- consumes canonical fields only;
- never replaces structured evidence;
- does not infer malicious intent or unsupported causality;
- quotes ambiguous arguments;
- omits itself for unsupported event families.

Renderer version `1` currently supports process execution messages backed by a named `execve`/`execveat` syscall or reconstructed `argv`. Merely having an executable path is not treated as evidence of a new process execution. Additional event-family templates belong to the extended-normalization milestone.

## Example and validation

`testdata/execve.v0.2.json` is the intentionally verbose golden event. It exercises:

- ENRICHED login, real, and effective identities that differ;
- a named syscall and correlated PID/PPID;
- multiple PATH objects and their operation roles;
- owner and group names;
- decoded non-empty file capabilities;
- the optional human renderer.

Ordinary events are smaller because equal identities, empty capabilities, integrity metadata, issues, source, and renderer fields are omitted.

## Backend boundary

Splunk CIM, Sentinel ASIM, Elastic ECS, aliases, calculated command lines, tags, detections, and risk classifications remain backend responsibilities.
