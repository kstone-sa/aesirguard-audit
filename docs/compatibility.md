# Compatibility

## Runtime

audit2json is a Linux-only Go program. Tagged releases contain static `linux/amd64` and `linux/arm64` binaries in standalone and systemd package variants. The standalone package has no service-manager assumption. The source has no CGO or external runtime dependency.

The parser accepts Linux Audit RAW and ENRICHED records. ENRICHED input is recommended because user names and architecture-dependent syscall names are then available without host-local lookup.

## Build compatibility

`go.mod` declares Go 1.22 minimum source compatibility. Official CI/package builds require the deliberately pinned Go version in `.go-version` (currently 1.26.8); unsupported old toolchains are not recommended for deployment. See [Development](development.md) for the policy. Package verification statically inspects both architectures and executes both variants on the runner's native architecture. This does not qualify arm64 execution or a Linux distribution/kernel/auditd combination.

## Distribution validation

| Distribution | Intended scope | Empirical status |
|---|---|---|
| Debian 12 and 13 | CIS Server Level 1 and 2 | Not yet empirically validated |
| Ubuntu 22.04 and 24.04 | CIS Server Level 1 and 2 | Not yet empirically validated |
| RHEL 8 and 9 | CIS Server Level 1 and 2 | Not yet empirically validated |
| Oracle Linux 8 and 9 | CIS Server Level 1 and 2 | Not yet empirically validated |

The distro-labelled fixtures are synthetic representatives. They verify deterministic parser and renderer behavior, not compatibility with every auditd and kernel combination.

## Operational compatibility

- Rename/create input rotation is supported and provides the strongest continuity guarantee.
- Retained, uncompressed numeric rotations such as `audit.log.1` are supported during recovery.
- Compressed rotations are not read.
- Copytruncate is detected as a source gap and is not claimed lossless.
- Configuration and checkpoint schema version 1 are supported. State paths reject symlink ancestors and special files; use real trusted directories rather than symlink aliases.
- Batch paths must be regular files; stdin supports streams. Physical-line bounds include terminators in both modes.
- Stdout and append-only managed-file sinks are supported. Backend-specific protocols and schemas are outside the core.
