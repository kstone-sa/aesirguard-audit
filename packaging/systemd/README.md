# Optional systemd deployment

For an existing deployment, read the [pre-1.0 migration guide](../../docs/rebranding.md) before changing paths or schema references.

These files turn the standalone AesirGuard Audit binary into a supervised host service. They are optional deployment material, not an RPM or DEB, and should be reviewed against the target distribution before installation.

## Install

Run the following as root from the extracted systemd archive:

```bash
install -m 0755 ag-audit /usr/bin/ag-audit
install -d -m 0755 /etc/aesirguard-audit
install -m 0644 configs/aesirguard-audit.example.json /etc/aesirguard-audit/config.json
install -m 0644 packaging/systemd/aesirguard-audit.sysusers.conf /usr/lib/sysusers.d/aesirguard-audit.conf
install -m 0644 packaging/systemd/aesirguard-audit.tmpfiles.conf /usr/lib/tmpfiles.d/aesirguard-audit.conf
install -m 0644 packaging/systemd/aesirguard-audit.service /usr/lib/systemd/system/aesirguard-audit.service
systemd-sysusers /usr/lib/sysusers.d/aesirguard-audit.conf
systemd-tmpfiles --create /usr/lib/tmpfiles.d/aesirguard-audit.conf
```

Grant the `aesirguard-audit` account read access to the active Audit log and retained rotations. Prefer setting auditd's `log_group` to `aesirguard-audit`; do not run the service as root merely to bypass log permissions.

Review `/etc/aesirguard-audit/config.json`, then validate and activate:

```bash
/usr/bin/ag-audit --config /etc/aesirguard-audit/config.json --check-config
systemctl daemon-reload
systemctl enable --now aesirguard-audit.service
systemctl status aesirguard-audit.service
```

With the example configuration, canonical events are written to stdout and therefore captured by journald. To feed a file-monitoring agent instead, set `sink.file` to a path below `/var/log/aesirguard-audit`; the supplied tmpfiles definition creates that directory.

## Remove

Stop and disable the service before removing its installed files:

```bash
systemctl disable --now aesirguard-audit.service
rm /usr/lib/systemd/system/aesirguard-audit.service
rm /usr/lib/sysusers.d/aesirguard-audit.conf
rm /usr/lib/tmpfiles.d/aesirguard-audit.conf
rm /usr/bin/ag-audit
systemctl daemon-reload
```

Configuration, checkpoints, output, and the service account are deliberately retained to prevent accidental data loss. Remove them only after reviewing `/etc/aesirguard-audit`, `/var/lib/aesirguard-audit`, and `/var/log/aesirguard-audit`.
