# Binary-only recovery qualification

The v0.10.1 release gate must include failed existing deployments. Clean-install
success alone is insufficient. `scripts/verify-upgrade.sh` is invoked by the shared
CI/tag verification gate and builds the immutable v0.10.0 source commit
`7744d4e9a510f88ebf60af6f9723640e916c6083` as the pre-fix executable, then the candidate.
The published v0.10.0 tag resolves to that same commit. No tags or releases are
created by this workflow. A complete local Git history is needed; CI fetches it.

For each scenario and both managed-file/stdout sinks, the old executable first
writes a real nonzero checkpoint and accepted output. The test then reproduces:

- a PATH-heavy event crossing the default 256-record bound and a fatal old exit;
- a source generation purged after checkpointing and a fatal old startup;
- both conditions together, including another oversized event in retained input.

The old checkpoint is verified unchanged after failure. The test starts the new
executable using exactly the old arguments, config defaults, paths, checkpoint and
output. No resets, manual recovery, migration command, or reinstall occurs.
It checks new valid events and a checkpoint tied to the actual new inode/offset,
then forcibly kills and restarts the process three times, appending new data.
Gap history must remain durable with exactly one incident, and later restarts must
not re-enter the same recovery transition. Oversized input must not produce fatal
errors or prevent subsequent events. Ordinary unit runs explicitly skip this
external-binary test; the mandatory script supplies both binaries and executes it.

Complementary deterministic tests exercise 255/256/257+ boundaries, EOE and
PROCTITLE, node interleaving, rejected-state bounds, inactivity fences, physical
line omission reporting, sink failure during exceptional output, live truncation,
unretained/missing rotations, oldest-contiguous salvage, anchor mismatches,
unsafe/corrupt ledger state, interrupted ledger/sink/checkpoint transitions, first-recovered-event output failure,
bounded persistent history, and fuzzed physical-payload accounting under pressure.

## Sustained-stream liveness regression

The original PR implementation renewed spill isolation on every new key and could
reject admission before pending expiration. A continuously busy source therefore
kept valid events exceptional and pinned its safe position indefinitely. The
simulated-time regression `TestRecoveringAssemblerSustainedStreamProgress` failed
on PR head `2052f64` at two seconds: ID `100.1:21` remained an
`ASSEMBLY_EXCEPTION`. It passes after pre-admission expiration and fencing only
untrackable unresolved input. It never calls idle `FlushExpired` and feeds new
records every 100ms across several one-second timeouts. Tests also cover continuous
compound events, timely interleaving, ordering on early-return paths, no duplicate
expiration, and live spilled tails retaining their original replay boundary.

`TestBusyFollowerCheckpointAndForcedRestart` starts actual follower subprocesses
against a prefilled source and uses a one-hour poll interval, so idle-poll expiration
cannot explain progress during its eight-second deadline. Production stdout over
an OS pipe and the managed file sink are both exercised. A test-only two-millisecond
sink delay makes the backlog span multiple 250ms timeouts. It checks
`valid -> pathological -> continuous valid` classification, explicitly preserved
exceptional/incomplete evidence, and a checkpoint beyond the pathological region
while unread input remains. It SIGKILLs the process, appends data, restarts with
identical application arguments/state, and verifies the retained backlog and new
events plus a valid source anchor. The test latency wrapper is removed on restart;
application configuration and checkpoint state are not changed.

The binary-only upgrade gate also exercises all three v0.10.0 failed-deployment
states with stdout as well as managed output. Stdout captures acceptance only;
these tests do not claim acknowledgement or durability from Splunk or another
external consumer. Managed output retains its stronger sync-before-checkpoint
boundary. The isolation fuzz campaign advances observation time between records
so it covers expiration during active streams as well as payload accounting.

No synthetic fixture certifies distribution compatibility or production safety.
The cause of unusually large groups in the rollout remains unproven. See
[the runbook](runbook.md) for a small-pilot operational validation plan and
[Reliability](reliability.md) for replay, conservative isolation, storage-failure,
and irreversible-loss limitations. No rollout is performed by the verification gate.
