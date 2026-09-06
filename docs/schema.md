# Canonical JSON schema

## Status

Canonical schema v1.0 is the pre-release event contract and the only event output. There is no legacy schema mode.

Output is newline-delimited JSON: one logical Linux Audit event per line. Empty optional objects, fields, and arrays are omitted. Fields documented as arrays never change to scalars.

Within schema major version 1, field types and documented semantics are stable. Compatible revisions may add optional fields; consumers must ignore fields they do not use. Removing a field, changing its type or meaning, or making an optional field required needs a new schema major version and migration documentation.

The machine-readable contract is `schema/audit2json-v1.schema.json`. The Go model and the published schema version are checked together by the test suite.

## Security-oriented boundary

The parser retains source records while assembling an event, but the canonical output is not a JSON copy of auditd. It emits fields with defined security or forensic meaning.

Unsupported record families are reported through `event.issues`; arbitrary source fields are not copied into normal events. A malformed physical line is the sole exception: it is emitted as a `parse_failure` event with the original line in `audit.raw`, preventing silent loss while keeping raw auditd noise out of valid events.

## Top-level contract

| Field | Type | Meaning |
|---|---|---|
| `schema_version` | string | Canonical schema version; currently `1.0` |
| `audit` | object | Original Audit ID and event time |
| `source` | object | Optional explicitly configured source host |
| `event` | object | Event type, outcome, integrity anomalies, and conversion issues |
| `rule` | object | Local Audit rule keys |
| `actor` | object | Login identity |
| `process` | object | Effective process identity and execution data |
| `target` | object | Account, service, or named object affected by the event |
| `origin` | object | Remote address, host, and terminal supplied by the producer |
| `security` | object | Mandatory access-control decision and policy context |
| `paths` | array | Ordered file objects with associated metadata |
| `message` | string | Optional deterministic analyst-readable message |
| `renderer_version` | string | Renderer template version, present only with `message` |

A local rule key is never used as a portable event type.

## Audit envelope and source

`audit.id` preserves the original `timestamp:serial` identifier used to correlate the physical records. `audit.time` is its UTC RFC 3339 representation. `audit.raw` appears only on malformed-line fallback events.

An invalid ID remains in `audit.id`; `audit.time` is omitted and `event.issues` reports `invalid_audit_id`.

`source` is omitted by default. `source.host` is emitted only when `--source-host` is supplied; the Audit `node` field is not copied automatically because collecting backends commonly attach source identity themselves. Boot identity belongs to collector and checkpoint state and is not repeated in every event.

## Event metadata

| Field | Type | Meaning |
|---|---|---|
| `event.type` | string | Deterministic primary Linux Audit record type |
| `event.category` | string | SIEM-agnostic semantic category such as `process`, `file`, or `configuration` |
| `event.action` | string | Stable semantic action used by renderers and backend adapters |
| `event.original_action` | string | Optional source operation such as a PAM operation; never used instead of the stable action |
| `event.success` | boolean | Normalized source result when recognized |
| `event.integrity` | object | Present only for incomplete events |
| `event.issues` | array | Present only for invalid or unsupported input |

Normal EOE and known single-record completions add no assembly metadata. Timeout, watermark, shutdown, or EOF flushes produce:

```json
"integrity": {
  "state": "incomplete",
  "reason": "timeout"
}
```

Unknown result values and unsupported record families are reported explicitly without copying their arbitrary fields.

## Target, origin, and security context

`target` is intentionally narrow. It can contain `user` or `user_id`, `service`, and `name`. Account names from `acct` are preferred; a numeric account is kept in `user_id`. Audit placeholders such as `?`, `unset`, and `(none)` are omitted.

`origin` can contain `address`, `host`, and `terminal`. It represents connection or authentication origin supplied by the event producer and is independent from the configured collector `source`.

`security` is emitted only for security, integrity, and access-control families. It can contain a normalized `decision`, ordered `permissions`, subject and target security contexts, target class, policy profile, and a boolean permissive-mode indicator. SELinux/AppArmor context is not repeated on unrelated authentication or lifecycle events merely because a `subj` field exists.

## Identity handling

Audit `log_format=ENRICHED` is required for the targeted CIS renderer behavior. ENRICHED names are preferred because they represent the account resolution performed when auditd wrote the event. Distribution-specific compatibility has not yet been empirically validated.

RAW input remains accepted. When an interpreted name is unavailable, the raw numeric identifier is emitted in a separate `*_id` field. A numeric value is never placed in a name field. Classification may be less specific when RAW input exposes only architecture-dependent syscall numbers.

`actor.user` or `actor.user_id` represents the login identity derived from AUID. Process identities are collapsed:

- effective process identity is omitted when equal to the login identity;
- real process identity is omitted when equal to either login or effective identity;
- differing identities use `process.user` or `process.user_id`, and `process.real_user` or `process.real_user_id`.

SUID, FSUID, SGID, FSGID, and their interpreted forms are not emitted.

## Process data

The process object may contain:

- `pid` and `ppid`, retained for process correlation and tree reconstruction;
- `name`, `executable`, `cwd`, and `tty`;
- `argv`, always an array preserving validated argument boundaries;
- `argv_source` (`execve` or `proctitle`), retaining the distinction between execution evidence and process context, including when invalid arguments are withheld;
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

Renderer version `3` covers the Linux Audit activity families selected by the targeted CIS Server L1+L2 profiles plus the security-event families in `security-event-coverage.md`. Process execution messages require a named `execve`/`execveat` syscall or reconstructed `argv`; merely having an executable path is not treated as execution evidence.

Classification uses reconstructed execution evidence, normalized syscall and outcome, normalized rule keys, and conservatively matched paths. Rule keys are locally configurable and therefore are not the sole contract. A security-relevant path is accepted without a recognized key only when the syscall itself proves a mutation. See `cis-coverage.md` for the supported baseline and family matrix.

Some user-space Audit records embed a second key/value payload inside `msg`. The parser extracts that payload without copying it wholesale. Recognized standalone user-space, lifecycle, and audit-daemon records complete immediately; kernel security records such as `AVC`, `SECCOMP`, and `BPF` continue to wait for `EOE` or the normal assembler boundary because they may be part of a compound event.

## Example and validation

`testdata/execve.v1.json` is the intentionally verbose golden event. It exercises:

- ENRICHED login, real, and effective identities that differ;
- a named syscall and correlated PID/PPID;
- multiple PATH objects and their operation roles;
- owner and group names;
- decoded non-empty file capabilities;
- the optional human renderer.

Ordinary events are smaller because equal identities, empty capabilities, integrity metadata, issues, source, and renderer fields are omitted.

## Backend boundary

Splunk CIM, Sentinel ASIM, Elastic ECS, aliases, calculated command lines, tags, detections, and risk classifications remain backend responsibilities.

## Pre-1.0 byte and argument integrity decision

Before the first stable release, v1 gains `process.argv_source`, `audit.raw_encoding`, and the optional issue properties `value_encoding`, `record_index`, `quoted`, and `source`. Existing ordinary text fields and array types remain unchanged. These additions preserve materially useful execution provenance and exceptional byte evidence without adding copies of normal raw records.

The parser recognizes the real ENRICHED separator (byte `0x1d`) outside quoted text and retains raw/interpreted and embedded field provenance. Audit quoted strings are literal: backslashes are not C or JSON escapes. Known untrusted-string fields are hex-decoded when unquoted; quoted hex-looking text stays literal. Nonhex userspace spellings remain text for compatibility. EXECVE and PROCTITLE use strict quoted-or-hex decoding.

A text value that cannot be represented as UTF-8 is withheld from its ordinary canonical field and reported as `invalid_utf8`. Its issue preserves the exact original field value bytes as hex in `value`, with `value_encoding: "hex"`, original field name in `field`, `record_type`, zero-based event `record_index`, Boolean `quoted`, and `source` (`raw`, `interpreted`, or `embedded`). Decode the issue value to recover the source token, then use its quoting and field semantics to interpret it. An omitted value with hex encoding denotes empty source bytes. No U+FFFD replacement is used as a substitute for the original evidence.

EXECVE argv is emitted only when argc, argument indexes, fragment indexes, duplicate values, encoded lengths and UTF-8 consistency establish a complete sequence. Length validation counts raw hex characters for hex fragments and literal bytes excluding quotes for quoted fragments, matching the kernel's `aN_len` convention. Fragments are joined as bytes before UTF-8 validation. No allocation is based on an untrusted argc/index. Incomplete, conflicting or invalid argv is withheld as a whole, retaining every available argc/length/argument/fragment in `incomplete_argv` issues with the same source provenance. Empty arguments remain valid array elements. PROCTITLE never conceals an incomplete EXECVE sequence; it is a fallback only when no EXECVE record exists.

Malformed physical lines remain in `audit.raw`. If the line itself is not UTF-8, that field contains hex bytes and `audit.raw_encoding` is `hex`; otherwise the original text behavior is unchanged. Consumers must check this marker when extracting malformed-line evidence.
