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
null rule-key and unset-AUID semantic gaps addressed in the v0.9.1 correction
line; the published v0.9.0 artifact is unchanged. Local regression tests of those
corrections do not substitute for a new native platform qualification run.

## Operational compatibility

- Rename/create input rotation is supported and provides the strongest continuity guarantee.
- Retained, uncompressed numeric rotations such as `audit.log.1` are supported during recovery.
- Compressed rotations are not read.
- Copytruncate is detected as a source gap and is not claimed lossless.
- Configuration schema version 1 and checkpoint schema version 2 are supported. Checkpoint version 1 is rejected; there is no automatic migration. State paths reject symlink ancestors and special files; use real trusted directories rather than symlink aliases.
- Batch paths must be regular files; stdin supports streams. Physical-line bounds include terminators in both modes.
- Stdout and append-only managed-file sinks are supported. Backend-specific protocols and schemas are outside the core.
