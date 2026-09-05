# Optional systemd deployment

These files turn the standalone audit2json binary into a supervised host service. They are optional deployment material, not an RPM or DEB, and should be reviewed against the target distribution before installation.

## Install

Run the following as root from the extracted systemd archive:

```bash
install -m 0755 audit2json /usr/bin/audit2json
install -d -m 0755 /etc/audit2json
install -m 0644 configs/audit2json.example.json /etc/audit2json/config.json
install -m 0644 packaging/systemd/audit2json.sysusers.conf /usr/lib/sysusers.d/audit2json.conf
install -m 0644 packaging/systemd/audit2json.tmpfiles.conf /usr/lib/tmpfiles.d/audit2json.conf
install -m 0644 packaging/systemd/audit2json.service /usr/lib/systemd/system/audit2json.service
systemd-sysusers /usr/lib/sysusers.d/audit2json.conf
systemd-tmpfiles --create /usr/lib/tmpfiles.d/audit2json.conf
```

Grant the `audit2json` account read access to the active Audit log and retained rotations. Prefer setting auditd's `log_group` to `audit2json`; do not run the service as root merely to bypass log permissions.

Review `/etc/audit2json/config.json`, then validate and activate:

```bash
/usr/bin/audit2json --config /etc/audit2json/config.json --check-config
systemctl daemon-reload
systemctl enable --now audit2json.service
systemctl status audit2json.service
```

With the example configuration, canonical events are written to stdout and therefore captured by journald. To feed a file-monitoring agent instead, set `sink.file` to a path below `/var/log/audit2json`; the supplied tmpfiles definition creates that directory.

## Remove

Stop and disable the service before removing its installed files:

```bash
systemctl disable --now audit2json.service
rm /usr/lib/systemd/system/audit2json.service
rm /usr/lib/sysusers.d/audit2json.conf
rm /usr/lib/tmpfiles.d/audit2json.conf
rm /usr/bin/audit2json
systemctl daemon-reload
```

Configuration, checkpoints, output, and the service account are deliberately retained to prevent accidental data loss. Remove them only after reviewing `/etc/audit2json`, `/var/lib/audit2json`, and `/var/log/audit2json`.
