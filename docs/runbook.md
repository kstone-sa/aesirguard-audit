# Operations runbook

## Install

Choose the standalone archive for a scheduler, container, custom supervisor, or direct execution. It contains the static binary and operational material but no service-manager files.

Verify and extract it without installing host-service assets:

```bash
sha256sum -c SHA256SUMS
tar -xzf audit2json_VERSION_linux_ARCH_standalone.tar.gz
cd audit2json_VERSION_linux_ARCH_standalone
./audit2json --version
./audit2json --config configs/audit2json.example.json --check-config
```

Consumers such as Splunk may execute this binary directly and consume canonical NDJSON from stdout. The standalone archive does not create users, directories, configuration, or services.

Choose the systemd archive for a host service. Install its binary as `/usr/bin/audit2json`, install the supplied sysusers, tmpfiles, and systemd unit files, then run the platform equivalents of `systemd-sysusers` and `systemd-tmpfiles --create`. The unit creates the private `/run/audit2json` lock directory through `RuntimeDirectory=` on every start.

The exact destination paths and activation sequence are documented in `packaging/systemd/README.md` inside that archive. Review the unit and configuration before enabling it; the files are portable deployment material, not a distro-native RPM or DEB.

The service account must be able to read the active Audit log and retained rotations. Prefer configuring auditd's `log_group` for the `audit2json` group instead of running the collector as root. Verify the resulting Audit log mode and group after restarting auditd; distro defaults differ.

Place a root-owned configuration at `/etc/audit2json/config.json` with mode `0644` or stricter in a directory that is not group- or world-writable. Validate it before starting:

```bash
audit2json --config /etc/audit2json/config.json --check-config
audit2json --version
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
- Output failure: restore space and permissions, then restart. Events after the last durable checkpoint may replay.
- Same-inode truncation: investigate the rotation policy. Do not treat an automatic restart at offset zero as lossless recovery.

## Upgrade and rollback

Before an upgrade, retain the previous binary and configuration, stop the process cleanly, back up the checkpoint, validate the existing configuration with the candidate binary, and inspect `audit2json --version`.

Version 1 configuration and checkpoint files are never rewritten into a different schema implicitly. A release that cannot read an existing version must fail before collection. Rollback therefore consists of restoring the previous binary and its configuration; restore the checkpoint backup only if a release explicitly introduced a documented checkpoint migration.

After restart, verify `started`, `recovery_started`, `recovery_caught_up`, heartbeat, lag, and gap counters before declaring the upgrade complete.
