# CIS Linux Audit coverage

## Scope

The intended validation target is the union of Linux Audit event-collection recommendations in CIS Server Level 1 and Level 2 for:

| Platform | Reference baseline |
|---|---|
| Debian 12 | CIS Debian 12 Benchmark v1.1.0 |
| Debian 13 | CIS Debian 13 Benchmark v1.0.0 |
| Ubuntu 22.04 LTS | CIS Ubuntu Linux 22.04 LTS Benchmark v2.0.0 |
| Ubuntu 24.04 LTS | CIS Ubuntu Linux 24.04 LTS Benchmark v1.0.0 |
| Red Hat Enterprise Linux 8 | CIS RHEL 8 Benchmark v4.0.0 |
| Red Hat Enterprise Linux 9 | CIS RHEL 9 Benchmark v2.0.0 |
| Oracle Linux 8 | CIS Oracle Linux 8 Benchmark v4.0.0, RHEL-compatible audit overlay |
| Oracle Linux 9 | CIS Oracle Linux 9 Benchmark v2.0.0, RHEL-compatible audit overlay |

Recommendation numbers are documentation references, not runtime identifiers. They differ between releases even when the audited activity is unchanged.

The targeted semantic coverage is designed for `auditd` using `log_format=ENRICHED`. RAW input is still parsed and retains numeric identity and architecture-dependent syscall fallbacks, but it may not contain enough portable evidence to select every renderer template.

## Semantic coverage

| CIS audit activity | Canonical category/action | Renderer behavior |
|---|---|---|
| Sudoers and administration scope changes | `configuration/change_privilege_scope` | Identifies the actor and changed sudo path |
| Actions executed as another user | `process/execute` | Identifies actor, effective identity, executable, and arguments |
| Sudo log modification | `file/write_sudo_log` | Identifies the actor and configured log path when present |
| Date and time changes | `system/change_time` | Names the time-changing syscall or `/etc/localtime` |
| Network environment changes | `configuration/change_network_configuration` | Identifies hostname, hosts, NetworkManager, netplan, or distro network paths |
| Privileged command use | `process/execute` | Identifies command, arguments, result, and effective identity |
| Unsuccessful file access | `file/access` | States that access failed and identifies syscall and path |
| User and group configuration changes | `configuration/change_identity_configuration` | Identifies the affected identity/PAM configuration path |
| DAC permission and ownership changes | `file/change_permissions` | Identifies syscall and affected path |
| Filesystem mounts | `system/mount_filesystem` | Identifies the mount operation and available target path |
| Session initiation records | `session/update_session_record` | Identifies utmp, wtmp, or btmp updates |
| Login and logout records | `authentication/update_login_record` | Identifies faillock, faillog, or lastlog updates |
| File deletion | `file/delete` | Identifies the deleted path |
| File rename | `file/rename` | Identifies source and destination when PATH roles provide both |
| Mandatory access-control policy changes | `configuration/change_mac_policy` | Covers SELinux and AppArmor policy paths |
| `chcon`, `setfacl`, and `chacl` use | `process/execute` | Renders the executed command and arguments |
| `usermod` use | `process/execute` | Renders the executed command and arguments |
| Kernel module loading | `system/load_kernel_module` or `process/execute` | Covers module syscalls and kmod-family commands |
| Kernel module unloading/query | `system/unload_kernel_module` or `system/query_kernel_module` | Names the module syscall and available path |

Changes to Audit configuration are additionally classified as `configuration/change_audit_configuration`, although CIS treats immutability primarily as a configuration requirement rather than a collected-event family.

## Matching contract

Classification prefers semantic evidence:

1. reconstructed execution evidence;
2. ENRICHED syscall name and normalized result;
3. normalized Audit rule keys;
4. exact or prefix-matched security-relevant paths only when paired with a clearly mutating syscall.

Common keys such as `time-change`, `system-locale`, `identity`, `perm_mod`, `mounts`, `session`, `logins`, `delete`, `MAC-policy`, `scope`, and `sudo_log_file` are recognized after case and hyphen normalization. A custom key still classifies when the syscall itself is decisive. Path plus `open`/`openat` is deliberately insufficient because Audit does not expose the open flags as a normalized syscall name; treating every read of `/etc/passwd` as a configuration change would be false.

Renderer wording follows the tri-state result: past tense for success, `failed to` for failure, and `attempted to` when the result is unavailable. It never converts an unknown outcome into a success claim.

## Validation

- table-driven classifier tests exercise every canonical family and recent syscall variants such as `fchmodat2` and `renameat2`;
- renderer tests require a deterministic message for every classified family;
- synthetic representative fixtures cover Debian, Ubuntu, RHEL, and Oracle path overlays;
- unsupported or insufficiently evidenced activity receives no invented message.

The mapping is versioned in `data/cis_audit_families.json`. Updating a CIS baseline requires updating this matrix, mapping data, and the affected fixtures together.

These fixtures validate the current semantic contract but are not an empirical distribution corpus. Controlled local testing with real RAW and ENRICHED Level 1 and Level 2 Audit output from every listed platform has not yet been completed. Until then, distribution-specific coverage is a target rather than a verified compatibility claim.

Rule keys are policy labels, not mutation evidence. A matched key without a
supported operation now yields `observe_<category>_activity`. A path-based
mutation classification requires a known modifying syscall; write-family calls
also require a positive byte count. `adjtimex`, `clock_adjtime`, and
`settimeofday` remain neutral because their pointer arguments do not establish
whether state was changed. Renderer version 5 uses neutral activity wording
for these cases. Specific operation actions describe the attempted operation;
only an explicit successful result permits successful-operation wording. This
is not a before/after state-difference proof or a claim of malicious intent.
