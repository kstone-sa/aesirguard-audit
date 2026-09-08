# Pre-1.0 migration to AesirGuard Audit

The product **audit2json** was renamed to **AesirGuard Audit** before v1.0.
Published [audit2json v0.9.0](https://github.com/kstone-sa/audit2json/releases/tag/v0.9.0)
and [audit2json v0.9.1](https://github.com/kstone-sa/audit2json/releases/tag/v0.9.1)
remain immutable historical releases, including their tags and original asset names.
**v0.10.0 is intended to be the first AesirGuard Audit release.** These source
changes do not create a tag or publish that release. Instructions on this branch
use the new names; use the documentation shipped with older release archives for
those binaries.

## Identity and contracts

| Surface | Historical name | New canonical name |
| --- | --- | --- |
| Product | audit2json | AesirGuard Audit |
| Core repository/module | `github.com/kstone-sa/audit2json` | `github.com/kstone-sa/aesirguard-audit` |
| Executable / command source | `audit2json` / `cmd/audit2json` | `ag-audit` / `cmd/ag-audit` |
| Archive prefix | `audit2json_VERSION_linux_ARCH_VARIANT` | `aesirguard-audit_VERSION_linux_ARCH_VARIANT` |
| Example configuration | `configs/audit2json.example.json` | `configs/aesirguard-audit.example.json` |
| Unit / sysusers / tmpfiles prefix | `audit2json` | `aesirguard-audit` |
| Service account and group | `audit2json` | `aesirguard-audit` |
| Configuration / state / runtime / output directories | `/etc/audit2json`, `/var/lib/audit2json`, `/run/audit2json`, `/var/log/audit2json` | `/etc/aesirguard-audit`, `/var/lib/aesirguard-audit`, `/run/aesirguard-audit`, `/var/log/aesirguard-audit` |
| Automatic per-user lock directory | `${TMPDIR:-/tmp}/audit2json-UID` | `${TMPDIR:-/tmp}/aesirguard-audit-UID` |
| Checkpoint temporary-file prefix | `.audit2json-checkpoint-` | `.aesirguard-audit-checkpoint-` |
| JSON Schema filename | `schema/audit2json-v1.schema.json` | `schema/aesirguard-audit-v1.schema.json` |

Canonical event schema remains **1.0**, checkpoint schema remains **2**, and
renderer version remains **5**. Configuration keys and configuration version 1
are unchanged. Parser, assembler, recovery, rotation, security and provenance
contracts are unchanged. The minimum Go version and pinned release toolchain
policy are unchanged. This is a pre-1.0 integration migration, not a stable-v1
compatibility promise. There is one executable; no legacy binary shim is shipped.
`BUILD-INFO.json` adds product and binary identity metadata; its version, commit,
toolchain and digest fields keep their meanings.

## Schema identity decision: clean filename rename (B)

There is one maintained schema, with `$id`:

```text
https://raw.githubusercontent.com/kstone-sa/aesirguard-audit/main/schema/aesirguard-audit-v1.schema.json
```

There is no old-filename alias or duplicate schema. Update validator paths,
vendored-schema references and `$id` caches explicitly. Only the schema title and
`$id` change; constraints, canonical JSON keys, `schema_version: "1.0"`, and event
semantics remain unchanged. Historical tags still contain their original schema.

## Deployment cutover

1. Stop and disable the old service or scripted input, and wait for its process
   to exit cleanly. Do this before enabling the new collector. Different lock
   paths do not provide mutual exclusion between old and new deployments. Do not
   unlink a lock file while any process may still hold it.
2. Back up the existing configuration and checkpoint. Install `ag-audit` and the
   new deployment artifacts following the [runbook](runbook.md) and, for a
   service deployment, the instructions included in the systemd archive. Review custom supervisors, monitoring agents and log
   rotation rules for executable, account, service and path references.
3. Preserve the existing **v2 checkpoint bytes**. Either explicitly configure its
   existing path, with appropriate access, or move/copy the checkpoint intact to
   the new private state directory while the old collector is stopped. Preserve
   the Audit source files and retained rotations; do not edit offsets, identity
   or content anchors. Merely renaming deployment paths does not require replay
   or checkpoint reinitialization. An absent checkpoint starts a replay; do not
   accidentally leave the old state behind and assume it was migrated.
4. When using the new service account, adjust ownership of the chosen state and
   output files/directories to it. Preserve private checkpoint/lock permissions
   and restrictive directory modes. Configure narrowly scoped Audit read access
   for the new group, including retained rotations. Do not relax hardening or
   global Audit permissions. Old state paths require corresponding systemd
   `ReadWritePaths` overrides; the default unit permits the new paths only.
5. Set the intended lock and checkpoint paths in the configuration; keep any
   existing managed output intact. Run `ag-audit --config ... --check-config`,
   then enable exactly one collector. Check source continuity, gap diagnostics,
   output and at-least-once replay handling. Configuration validation alone does
   not exercise every runtime filesystem permission or source anchor.

Checkpoint v1 is still rejected; its explicit replay procedure is documented in
[the runbook](runbook.md). Changing a filename must never be used to bypass that
rejection. For rollback, stop the new collector first and use the saved old
binary/configuration with the latest compatible v2 checkpoint, not a stale
pre-cutover copy unless deliberate replay is wanted.

## Repository and Splunk consumers

Use [the new core URL](https://github.com/kstone-sa/aesirguard-audit) and
[the new Splunk TA URL](https://github.com/kstone-sa/splunk-ta-aesirguard-audit).
GitHub's old repository URLs may redirect after the maintainer renames the
repositories, but consumers should update remotes, module imports, automation and
cross-links to the new canonical URLs. The new URLs need not resolve before that
separate repository rename. Neither repository is renamed by these content changes.

The TA becomes **AesirGuard Audit Splunk TA**, app ID `TA-aesirguard-audit`, with
`bin/ag-audit`, wrapper `bin/aesirguard-audit-wrapper.sh`, sourcetype
`aesirguard:linux:audit` and source `aesirguard-audit`. Its migration guide covers
historical indexed events and search updates; no dual-sourcetype alias is shipped.

## Retained historical evidence

The sanitized `testdata/user_cmd.audit` fixture contains the observed source CWD
`/home/test/audit2json`; its matching assertion remains intact. That value is
historical Audit evidence, not an installation path or executable recommendation.
