# Operations runbook

For an existing deployment, read the [pre-1.0 migration guide](rebranding.md) before changing paths or schema references.

## Install

Choose the standalone archive for a scheduler, container, custom supervisor, or direct execution. It contains the static binary and operational material but no service-manager files.

Verify and extract it without installing host-service assets:

```bash
set -euo pipefail
archive=aesirguard-audit_VERSION_linux_ARCH_standalone.tar.gz
# Select exactly one manifest entry; do not require the three unselected files.
awk -v file="./$archive" '$2 == file { print; n++ } END { if (n != 1) exit 1 }' SHA256SUMS > selected.sha256 &&
  sha256sum -c selected.sha256 &&
  tar -xzf "$archive"
cd aesirguard-audit_VERSION_linux_ARCH_standalone
./ag-audit --version
./ag-audit --config configs/aesirguard-audit.example.json --check-config
```

Consumers such as Splunk may execute this binary directly and consume canonical NDJSON from stdout. The standalone archive does not create users, directories, configuration, or services.

Choose the systemd archive for a host service. Install its binary as `/usr/bin/ag-audit`, install the supplied sysusers, tmpfiles, and systemd unit files, then run the platform equivalents of `systemd-sysusers` and `systemd-tmpfiles --create`. The unit creates the private `/run/aesirguard-audit` lock directory through `RuntimeDirectory=` on every start.

The exact destination paths and activation sequence are documented in `packaging/systemd/README.md` inside that archive. Review the unit and configuration before enabling it; the files are portable deployment material, not a distro-native RPM or DEB.

The service account must be able to read the active Audit log and retained rotations. Prefer configuring auditd's `log_group` for the `aesirguard-audit` group instead of running the collector as root. Verify the resulting Audit log mode and group after restarting auditd; distro defaults differ.

Place a root-owned configuration at `/etc/aesirguard-audit/config.json` with mode `0644` or stricter in a directory that is not group- or world-writable. Validate it before starting:

```bash
ag-audit --config /etc/aesirguard-audit/config.json --check-config
ag-audit --version
```

Enable the service only after configuring auditd for rename/create rotation and ensuring rotated files remain uncompressed long enough for the collector to drain them.

## Monitor

Canonical events go to stdout or the managed file sink. Diagnostics go to stderr/journald. Alert on:

- missing heartbeats beyond the configured interval and restart tolerance;
- `source_gap`, `fatal`, or repeated restart records;
- non-zero gap counters;
- sustained input lag approaching the retained rotation capacity;
- repeated parse failures.

A scheduled Splunk scripted input may invoke the binary repeatedly. The singleton lock makes a second invocation exit successfully while the existing process owns the input. A service manager should use `Restart=on-failure` for unexpected exits.

## Recover

Do not delete or edit a checkpoint to conceal a startup error. First preserve the checkpoint, active log, and retained rotations.

- Missing checkpoint generation: restore the matching uncompressed rotation or explicitly accept a gap before starting a new state lineage.
- Corrupt or unsupported checkpoint: restore the last known-good checkpoint or roll back to the compatible binary. The collector fails closed.
- Output failure: preserve the output and checkpoint, restore space and permissions, and inspect the final physical line. An incomplete tail deliberately blocks restart. Repair that incomplete line or quarantine the affected file only after preserving it; do not append a newline to an incomplete JSON object. Then restart. Events after the last durable checkpoint may replay.
- Same-inode truncation: investigate the rotation policy. Do not treat an automatic restart at offset zero as lossless recovery.

## Upgrade and rollback

Before an upgrade, retain the previous binary and configuration, stop the process cleanly, back up the checkpoint, validate the existing configuration with the candidate binary, and inspect `ag-audit --version`.

Configuration version 1 remains supported. Checkpoint version 2 adds a required content anchor; version 1 checkpoints are rejected and never implicitly migrated. To upgrade from checkpoint v1, retain all input generations, archive the old checkpoint, and explicitly replay the retained files from their beginnings into the downstream deduplication workflow before starting a new v2 follower checkpoint. Do not manufacture an anchor for an old offset: the historical identity cannot be established safely. A rollback to a v1-only binary likewise requires an explicit replay plan; it cannot consume v2 state. A release that cannot read an existing version must fail before collection. Rollback therefore consists of restoring the previous binary and its configuration; restore the checkpoint backup only if a release explicitly introduced a documented checkpoint migration.

After restart, verify `started`, `recovery_started`, `recovery_caught_up`, heartbeat, lag, and gap counters before declaring the upgrade complete.
