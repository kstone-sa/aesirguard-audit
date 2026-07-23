# Compact JSON schema

The output is newline-delimited JSON. Each line represents one audit event.

Only populated fields are emitted.

| Field | Meaning |
|---|---|
| `id` | Audit ID in `timestamp:serial` form |
| `key` | auditd rule key |
| `type` | Record type fallback when no key is available |
| `res` | Result value |
| `auid` | Audit user ID |
| `uid` | User ID |
| `euid` | Effective user ID |
| `gid` | Group ID |
| `egid` | Effective group ID |
| `ses` | Audit session ID |
| `pid` | Process ID |
| `ppid` | Parent process ID |
| `arch` | Audit architecture code |
| `sc` | Syscall number or normalized name |
| `exe` | Executable path |
| `cmd` | Reconstructed command line |
| `cwd` | Current working directory |
| `path` | Single affected path |
| `paths` | Multiple affected paths |
| `tty` | Terminal |

Example:

```json
{"id":"1721721600.123:42","key":"privileged","res":"yes","auid":"1000","uid":"0","euid":"0","gid":"0","egid":"0","ses":"3","pid":"200","ppid":"100","arch":"c000003e","sc":"59","exe":"/usr/bin/sudo","cmd":"sudo cat /etc/shadow","cwd":"/home/mario","path":"/etc/shadow","tty":"pts0"}
```
