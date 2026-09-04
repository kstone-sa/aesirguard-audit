# Compatibility

## Runtime

audit2json is a Linux-only Go program. Tagged releases contain static `linux/amd64` and `linux/arm64` binaries. The source has no CGO or external runtime dependency.

The parser accepts Linux Audit RAW and ENRICHED records. ENRICHED input is recommended because user names and architecture-dependent syscall names are then available without host-local lookup.

## Distribution validation

| Distribution | Intended scope | Empirical status |
|---|---|---|
| Debian 12 and 13 | CIS Server Level 1 and 2 | Pending milestone 8B |
| Ubuntu 22.04 and 24.04 | CIS Server Level 1 and 2 | Pending milestone 8B |
| RHEL 8 and 9 | CIS Server Level 1 and 2 | Pending milestone 8B |
| Oracle Linux 8 and 9 | CIS Server Level 1 and 2 | Pending milestone 8B |

The distro-labelled fixtures are synthetic representatives. They verify deterministic parser and renderer behavior, not compatibility with every auditd and kernel combination.

## Operational compatibility

- Rename/create input rotation is supported and provides the strongest continuity guarantee.
- Retained, uncompressed numeric rotations such as `audit.log.1` are supported during recovery.
- Compressed rotations are not read.
- Copytruncate is detected as a source gap and is not claimed lossless.
- Configuration and checkpoint schema version 1 are supported.
- Stdout and append-only managed-file sinks are supported. Backend-specific protocols and schemas are outside the core.
