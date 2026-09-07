# Compatibility

## Runtime

audit2json is a Linux-only Go program. Tagged releases contain static `linux/amd64` and `linux/arm64` binaries in standalone and systemd package variants. The standalone package has no service-manager assumption. The source has no CGO or external runtime dependency.

The parser accepts Linux Audit RAW and ENRICHED records. ENRICHED input is recommended because user names and architecture-dependent syscall names are then available without host-local lookup.

## Build compatibility

`go.mod` declares Go 1.26 minimum source compatibility. Official CI/package builds require the deliberately pinned Go version in `.go-version` (currently 1.26.8). See [Development](development.md) for the policy. Package verification statically inspects both architectures and executes both variants on the runner's native architecture. This does not qualify arm64 execution or a Linux distribution/kernel/auditd combination.

## Distribution validation

| Distribution | Intended scope | Empirical status |
|---|---|---|
| Debian 12 and 13 | CIS Server Level 1 and 2 | Not yet empirically validated |
| Ubuntu 22.04 | CIS Server Level 1 and 2 | Not yet empirically validated |
| Ubuntu 24.04 | CIS Server Level 1 and 2 | ENRICHED arm64 empirically exercised; not fully qualified |
| RHEL 8 and 9 | CIS Server Level 1 and 2 | Not yet empirically validated |
| Oracle Linux 8 and 9 | CIS Server Level 1 and 2 | Not yet empirically validated |

The distro-labelled fixtures are synthetic representatives. They verify deterministic parser and renderer behavior, not compatibility with every auditd and kernel combination. Public 0.9.x releases are qualification pre-releases; they do not certify this matrix.

## Initial empirical exercise (2026-09-07)

Maintainer-reported qualification used the published, immutable v0.9.0
`audit2json_v0.9.0_linux_arm64_standalone.tar.gz`, commit
`4c8317c761ef4956f0acf836f719df6ff71108a9` (built
`2026-09-07T07:30:42Z`, Go 1.26.8), on Ubuntu 24.04.4 LTS,
arm64/aarch64, kernel `6.17.0-1029-nvidia`, auditd/auditctl 3.1.2,
with `log_format=ENRICHED`.

- Native published arm64 startup and version reporting succeeded.
- Configuration validation and real audit.log batch parsing succeeded.
- 63 emitted events were independently verified as valid JSON.
- Live `--follow --render-message` was exercised successfully.
- Observed families included audit daemon, audit configuration, service,
  authentication and session records.
- The observed live heartbeat reported `parse_failures=0`, `gaps=0`,
  `input_lag_bytes=0`, `pending_bytes=0` and `pending_events=0`.

This is an initial empirical exercise, not full Ubuntu 24.04 qualification.
Controlled event-family qualification is incomplete; RAW validation and platform
recovery/rotation qualification remain pending. No unobserved duration, workload,
family or architecture is certified by this run. The run also exposed USER_CMD,
null rule-key, unset-AUID and kernel LOGIN attribution semantic gaps addressed in the v0.9.1 correction
line; the published v0.9.0 artifact is unchanged. Local regression tests of those
corrections do not substitute for a new native platform qualification run.

## Controlled ENRICHED volume sample

The maintainer reported the following measurements from one controlled Ubuntu
24.04 arm64 ENRICHED qualification sample. This is a sample-specific volume
observation, not a general benchmark or performance guarantee. Event mix, Audit
rules and optional output fields affect the result; these numbers do not qualify
other workloads or establish complete distribution compatibility.

| Whole sample | Measured value |
|---|---:|
| Linux Audit source records | 175 |
| Raw bytes | 39,220 |
| Canonical events | 47 |
| Canonical bytes without renderer | 27,794 |
| Canonical bytes with `--render-message` | 32,393 |
| Byte reduction without renderer | 29.13% |
| Byte reduction with renderer | 17.41% |
| Renderer overhead relative to canonical output without renderer | 16.55% |

For the compound kernel-event subset, 158 Audit records became 30 canonical
events: 34,483 raw bytes became 21,388 canonical bytes, a 37.98% reduction and
an average of 5.27 source records per canonical event. Within the measured sample,
`process/execute` comprised 17 events from 102 source records: 21,490 raw bytes
became 12,371 canonical bytes, a 42.43% reduction.

| Other observed category/action | Byte reduction |
|---|---:|
| `session/observe_session_activity` | 25.68% |
| `file/change_permissions` | 27.74% |
| `file/delete` | 34.45% |
| `file/rename` | 46.14% |
| `file/access` | 27.30% |

Single-record userspace events expanded after canonical JSON normalization in
this sample. audit2json reduces volume primarily by collapsing compound Linux
Audit record groups into one canonical event. It is not a generic text compressor;
already compact single-record userspace events may become larger. Rendered messages
add convenience/debug text that duplicates canonical information, so they should
normally remain disabled for volume-sensitive SIEM ingestion.

The qualification Audit rules also had to be architecture-aware: an initial
x86-style rule containing legacy `open` was rejected on AArch64, while the
equivalent arm64 syscall set loaded successfully. This was a qualification-environment
observation, not an audit2json defect. Native arm64 requalification of the pushed
v0.9.1 candidate remains the next step before maintainer authorization of a release.

## Operational compatibility

- Rename/create input rotation is supported and provides the strongest continuity guarantee.
- Retained, uncompressed numeric rotations such as `audit.log.1` are supported during recovery.
- Compressed rotations are not read.
- Copytruncate is detected as a source gap and is not claimed lossless.
- Configuration schema version 1 and checkpoint schema version 2 are supported. Checkpoint version 1 is rejected; there is no automatic migration. State paths reject symlink ancestors and special files; use real trusted directories rather than symlink aliases.
- Batch paths must be regular files; stdin supports streams. Physical-line bounds include terminators in both modes.
- Stdout and append-only managed-file sinks are supported. Backend-specific protocols and schemas are outside the core.
