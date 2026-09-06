# Security event coverage beyond CIS

## Boundary

CIS Server Level 1 and Level 2 remain a validation profile, not the renderer boundary. The generic mapping in `data/security_event_families.json` classifies portable Linux Audit record types without introducing Splunk CIM, Sentinel ASIM, Elastic ECS, or another backend contract.

The canonical event keeps only fields with a stable security or forensic meaning. It does not expose an arbitrary source-field map. `event.type` preserves the primary Audit record type, `event.category` and `event.action` provide a stable semantic classification, and renderer version 3 derives an optional analyst-readable sentence from those canonical fields.

## Mapped families

| Family | Audit record types | Canonical intent |
|---|---|---|
| Authentication | `USER_AUTH`, `USER_ACCT`, `USER_LOGIN`, `USER_LOGOUT`, `CRED_ACQ`, `CRED_DISP`, `CRED_REFR`, `USER_ERR` | Authentication, account checks, login/logout, and credential lifecycle |
| Account lifecycle | `USER_CHAUTHTOK`, `GRP_CHAUTHTOK`, `USER_MGMT`, `GRP_MGMT`, `ADD_USER`, `DEL_USER`, `ADD_GROUP`, `DEL_GROUP`, `ACCT_LOCK`, `ACCT_UNLOCK` | Credential and account/group changes |
| Sessions | `USER_START`, `USER_END` | Session start and end |
| System and services | `SYSTEM_BOOT`, `SYSTEM_SHUTDOWN`, `SYSTEM_RUNLEVEL`, `SERVICE_START`, `SERVICE_STOP`, `SOFTWARE_UPDATE` | Host, service, and software lifecycle |
| Audit subsystem | `DAEMON_START`, `DAEMON_END`, `DAEMON_ABORT`, `DAEMON_ERR`, `DAEMON_CONFIG`, `DAEMON_ROTATE`, `DAEMON_RESUME`, `CONFIG_CHANGE`, `FEATURE_CHANGE` | Audit availability, rotation, errors, and configuration changes |
| Mandatory access control | `AVC`, `USER_AVC`, `SELINUX_ERR`, `USER_SELINUX_ERR`, `APPARMOR_DENIED`, `APPARMOR_ALLOWED`, `APPARMOR_KILL`, `APPARMOR_ERROR`, `APPARMOR_STATUS`, `MAC_STATUS`, `MAC_POLICY_LOAD` | SELinux/AppArmor decisions, failures, and policy state |
| Kernel security | `SECCOMP`, `BPF`, `CAPSET`, `BPRM_FCAPS`, `KERN_MODULE` | System-call filtering, BPF, capabilities, and module operations |
| Anomaly and integrity | `ANOM_*`, `INTEGRITY_*` | Stable umbrella classification while preserving the exact Audit type |

For compound events, a mapped security record such as `AVC` becomes the primary `event.type` while correlated `SYSCALL` process evidence remains available. A named module syscall still receives the more specific CIS action such as `load_kernel_module`; `KERN_MODULE` is the fallback when the source does not provide that evidence.

## Extracted evidence

- embedded user-space `msg` payloads supply result, source operation, target account, executable, remote address, host, and terminal;
- SELinux AVC prose supplies decision and ordered permission names;
- SELinux and AppArmor fields supply contexts, object class, profile, permissive mode, and named target when present;
- service unit and account names populate the typed `target` object;
- placeholders are omitted and unknown results remain explicit issues.

## Deliberate gaps

`SOCKADDR` binary address decoding, packet-level Netfilter records, IPC/message queues, virtualization, cryptographic/IPsec lifecycle, and TTY keystroke payloads are not normalized in this pass. They need dedicated typed objects and privacy/volume decisions; treating them as generic names or copying their raw fields would create a misleading contract.

These mappings are based on upstream Linux Audit record definitions and synthetic regression fixtures. Empirical RAW and ENRICHED validation on Debian, Ubuntu, RHEL, and Oracle Linux has not yet been completed and is not claimed by this document.

SECCOMP filtering is decoded by the action bits in `code`, not classified uniformly as blocking. `security.seccomp` preserves filter action, full code, signal, and instruction pointer; LOG, TRACE, and USER_NOTIF are distinguished from enforcement. Kernel configuration and policy records wait for a compound-event boundary. Mixed security families retain their decisions independently of primary-type selection; additional distinct contexts remain explicit issue evidence. See `schema.md` for the pre-1.0 contract additions.
