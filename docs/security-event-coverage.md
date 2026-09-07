# Security event coverage beyond CIS

## Boundary

CIS Server Level 1 and Level 2 remain a validation profile, not the renderer boundary. The generic mapping in `data/security_event_families.json` classifies portable Linux Audit record types without introducing Splunk CIM, Sentinel ASIM, Elastic ECS, or another backend contract.

The canonical event keeps only fields with a stable security or forensic meaning. It does not expose an arbitrary source-field map. `event.type` preserves the primary Audit record type, `event.category` and `event.action` provide a stable semantic classification, and renderer version 5 derives an optional analyst-readable sentence from those canonical fields.

## Classification and normalization are separate contracts

Recognition assigns a stable family/category/action to a known record type or prefix. It does **not** certify full normalization of that record's fields. `event.type` is the selected primary type, not an inventory of every correlated record. The absence of `unsupported_record` means recognition, not lossless field coverage. Normal events intentionally omit unmodeled source fields; retain the original Audit logs when investigations require full source detail.

All rows below recognize/classify the listed types. Typed values are conditional on actual source evidence; absence is never proof that an action, context or transition did not exist. Common projection includes `audit.id/time`, actor/process user IDs or supplied names, PID/PPID, executable/comm, `event.original_action` from `op`/`operation`, and rule keys when present. Correlated EXECVE, PROCTITLE, SYSCALL and PATH evidence follows the separate [schema contract](schema.md), including argv provenance and PATH file capabilities.

| Family and recognized types | Additional typed evidence in v1 | Classification-only or unmodeled detail |
|---|---|---|
| Authentication: `USER_AUTH`, `USER_ACCT`, `USER_LOGIN`, `USER_LOGOUT`, `CRED_ACQ`, `CRED_DISP`, `CRED_REFR`, `USER_ERR` | `event.success` for recognized results; `target.user/user_id` from acct; `origin.address/host/terminal` | Authentication mechanism-specific metadata and credential contents |
| Account lifecycle: `USER_CHAUTHTOK`, `GRP_CHAUTHTOK`, `USER_MGMT`, `GRP_MGMT`, `ADD_USER`, `DEL_USER`, `ADD_GROUP`, `DEL_GROUP`, `ACCT_LOCK`, `ACCT_UNLOCK` | Result; acct target; eligible userspace origin; source operation | No typed group membership delta, changed-account attribute set, or before/after credential state |
| Kernel Audit attribution: `LOGIN` | `session` / `set_audit_attribution`; `process.audit_attribution.old/new` retains loginuid, enriched user, session ID and explicit unset flags; own numeric result (0/1) | Sets or attempts to set kernel loginuid/session attribution; never equivalent to `USER_LOGIN`. Remains correlated with SYSCALL/PROCTITLE until EOE or an incomplete boundary; new values are applied only on success |
| Sessions: `USER_START`, `USER_END` | Result, acct target, userspace origin | No dedicated session lifecycle object or normalized session duration |
| System: `SYSTEM_BOOT`, `SYSTEM_SHUTDOWN`, `SYSTEM_RUNLEVEL` | Common projection and recognized result | Boot metadata and old/new runlevels are not normalized |
| Services/software: `SERVICE_START`, `SERVICE_STOP`, `SOFTWARE_UPDATE` | `target.service` from unit/service, `target.name` when supplied; result | Package version transitions, package identity beyond supplied name, dependency/install detail |
| Audit daemon: `DAEMON_START`, `DAEMON_END`, `DAEMON_ABORT`, `DAEMON_ERR`, `DAEMON_CONFIG`, `DAEMON_ROTATE`, `DAEMON_RESUME` | Common projection, source operation and recognized textual result | Daemon counters, error-specific fields and configuration deltas |
| Audit configuration: `CONFIG_CHANGE`, `FEATURE_CHANGE` | Common projection, rule key, source operation, typed numeric result (0/1) | Setting/feature identity and old/new values are not modeled as a configuration transition |
| SELinux decisions/errors: `AVC`, `USER_AVC`, `SELINUX_ERR`, `USER_SELINUX_ERR` | `security.decision/permissions/subject_context/target_context/target_class/permissive` where present; target name | No general policy-language/error payload decoder; an error-type label alone does not supply a decision |
| AppArmor: `APPARMOR_DENIED`, `APPARMOR_ALLOWED`, `APPARMOR_KILL`, `APPARMOR_ERROR`, `APPARMOR_STATUS` | Decision from apparmor/decision, requested_mask permissions, profile, contexts and target name when present | No comprehensive policy delta or type-inferred decision when decision fields are absent |
| MAC configuration: `MAC_STATUS`, `MAC_POLICY_LOAD` | Common projection, numeric result (0/1); supported context fields if supplied | Old/new enforcing state, policy identity/version and complete policy contents |
| Seccomp: `SECCOMP` | `security.seccomp.action/code/signal/instruction_pointer`, correlated syscall/process evidence; action-specific classification | No reconstruction of filter program or proof that the eventual syscall succeeded |
| BPF: `BPF` | Common projection and source operation | Program ID, program type, tag and program contents are not normalized |
| Process capabilities: `CAPSET`, `BPRM_FCAPS` | Common projection; correlated PATH file capabilities when present | Process before/after permitted/effective/inheritable sets are not normalized; PATH capabilities are a different feature |
| User commands: `USER_CMD` | `process` / `user_command`; decoded `process.command` with `command_source=user_cmd`, actor, PID, cwd, executable, terminal and source result | Command text has no reliable argv boundaries and does not prove execution or eventual command success; invalid/conflicting command tokens remain reversible issues |
| Modules: `KERN_MODULE` | Common projection, source operation/name when supplied; named init_module/finit_module/delete_module syscalls get the specific load/unload action | No dedicated module identity/signature/version object |
| Anomalies: `ANOM_*` | Exact primary type, umbrella classification, common projection and supported security context/decision fields if present | No decoder for each anomaly subtype or anomaly-specific counters/thresholds |
| Integrity: `INTEGRITY_*` | Exact primary type, umbrella classification, common projection, supplied name, recognized result and supported security contexts | No IMA/EVM digest, algorithm, signature or measurement object |

For compound events, mapped security evidence takes deterministic priority over ordinary syscall classification. AVC contexts remain separate from unrelated subjects. Additional distinct supported security decisions are retained in explicit issues; this does not extend preservation to all unmodeled fields in the table. Unknown/conflicting results and exceptional byte/argv evidence also remain explicit issues.

Renderer version 5 summarizes only the available canonical fields. It cannot reconstruct omitted transitions or provide richer semantics than the structured event. SECCOMP LOG, ALLOW, TRACE and USER_NOTIF are distinct from blocking; permissive denials do not imply enforcement or syscall success.

`USER_ACCT` validates a PAM account; `CRED_ACQ` acquires credentials; `USER_START` starts a PAM session; `USER_LOGIN` records a user login. `LOGIN` separately records the kernel Audit attribution transition and takes primary meaning over a correlated SYSCALL write. `testdata/login_transition.audit` preserves the sanitized real group with the actual ENRICHED 0x1d separators.

## Contract tests

`TestEveryAdvertisedFamilyHasAnExplicitCoverageBoundary` requires a documented entry for every mapped type/prefix and checks common evidence preservation. `TestClassificationOnlyDetailsDoNotMasqueradeAsTypedEvidence` records deliberate projection boundaries for capability, BPF, configuration, integrity and runlevel detail. Existing execution-provenance, result, mixed-security, seccomp and byte-integrity tests exercise the richer typed contracts. New normalization requires updating both tests and this matrix; recognition alone must never be promoted to full semantic coverage.

## Deliberate gaps

`SOCKADDR` binary address decoding, packet-level Netfilter records, IPC/message queues, virtualization, cryptographic/IPsec lifecycle, and TTY keystroke payloads are not normalized in this pass. They need dedicated typed objects and privacy/volume decisions; treating them as generic names or copying their raw fields would create a misleading contract.

These mappings are based on upstream Linux Audit record definitions and synthetic regression fixtures, supplemented by the initial Ubuntu USER_CMD format in `testdata/user_cmd.audit`. That sanitized fixture retains the real ENRICHED separator byte 0x1d before UID/AUID; plain-text pastes may hide that byte. Missing field boundaries remain malformed input, rather than triggering guessed repairs. See [Compatibility](compatibility.md) for the observed platform exercise. Empirical RAW and ENRICHED validation on Debian, Ubuntu, RHEL, and Oracle Linux has not yet been completed and is not claimed by this document.
