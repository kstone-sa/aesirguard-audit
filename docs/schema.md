# Canonical JSON schema

## Status

The current v0.1 output uses the compact fields documented below. The canonical schema described later in this document is a target and is not frozen or implemented yet.

Output is newline-delimited JSON: one logical Audit event per line. Empty fields, null values, and empty arrays are omitted.

## Current v0.1 fields

| Field | Meaning |
|---|---|
| `id` | Audit ID in timestamp:serial form |
| `key` | Local audit rule key |
| `type` | Record-type fallback when no key is available |
| `res` | Source result value |
| `auid` | Audit user ID |
| `uid` | User ID |
| `euid` | Effective user ID |
| `gid` | Group ID |
| `egid` | Effective group ID |
| `ses` | Audit session ID |
| `pid` | Process ID |
| `ppid` | Parent process ID |
| `arch` | Audit architecture code |
| `sc` | Syscall number |
| `exe` | Executable path |
| `cmd` | Reconstructed display command |
| `cwd` | Current working directory |
| `path` | Single affected path |
| `paths` | Multiple affected paths |
| `tty` | Terminal |

This schema is compact but loses fields required for broad Audit coverage and contains unstable semantics such as scalar-versus-array paths and conditional event type.

## Canonical-schema principles

The target schema must:

- remain independent from backend data models;
- carry a schema version;
- expose event time and serial separately from the source audit ID;
- include source identity sufficient to distinguish events from different hosts and boots;
- keep event type and local audit rule key independent;
- use stable JSON types;
- preserve argument boundaries instead of relying only on a display command;
- preserve repeated PATH records and their roles;
- distinguish source values from normalized values where interpretation can vary;
- retain unsupported security-relevant fields in a controlled fallback structure;
- identify incomplete, malformed, truncated, or recovered events;
- support deterministic optional human-readable rendering;
- avoid empty values and unnecessary duplication.

Field names remain compact because output size may affect ingestion cost, but compactness must not destroy meaning or type stability.

## Canonical event identity

The source audit ID is not globally unique. The target event identity must account for at least:

- source host identity;
- boot or equivalent source generation when available;
- Audit timestamp and serial.

The exact serialized form will be decided before the schema is frozen.

## Normalized and source values

Mappings must not silently replace evidence. For values such as syscall, architecture, errno, result, account identity, and permissions, retain the original representation whenever normalization could fail or vary by platform.

A field must not alternate between a numeric code and a textual name. Use separate fields when both representations are needed.

## Repeated data

A field must not change between scalar and array based on cardinality. EXECVE arguments and PATH records require stable repeated-value structures. PATH metadata such as item, name type, inode, device, mode, owner, and group must remain associated with the corresponding path.

## Event classification

Canonical event codes describe technical Linux activity, for example process execution, authentication, file activity, policy changes, or mandatory-access-control decisions.

Classification must be deterministic and evidence-based. Local rule keys are deployment metadata. Risk, threat, and detection conclusions belong to the backend.

## Human-readable message

An optional message may summarize the normalized event for analysts. It must:

- be deterministic and versioned;
- use normalized fields only;
- never be the sole representation of a fact;
- avoid unsupported causal or security conclusions;
- remain optional so consumers can minimize indexed volume.

## Backend adapters

Backend adapters may map the canonical event to Splunk CIM, Sentinel ASIM, Elastic ECS, or another model. Such mappings, aliases, calculated fields, tags, and detections are deliberately outside this schema.

## Compatibility

Once the canonical schema is declared stable:

- existing fields retain their meaning and JSON type;
- additive fields are preferred;
- incompatible changes require a schema-version change;
- mapping and renderer versions are reported separately from the schema version.
