# Binary-only recovery qualification

The v0.10.1 release gate must include failed existing deployments. Clean-install
success alone is insufficient. `scripts/verify-upgrade.sh` is invoked by the shared
CI/tag verification gate and builds the immutable v0.10.0 source commit
`7744d4e9a510f88ebf60af6f9723640e916c6083` as the pre-fix executable, then the candidate.
The published v0.10.0 tag resolves to that same commit. No tags or releases are
created by this workflow. A complete local Git history is needed; CI fetches it.

For each scenario the old executable first writes a real nonzero checkpoint and
managed output. The test then reproduces:

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

No synthetic fixture certifies distribution compatibility or production safety.
The cause of unusually large groups in the rollout remains unproven. See
[the runbook](runbook.md) for a small-pilot operational validation plan and
[Reliability](reliability.md) for replay, conservative isolation, storage-failure,
and irreversible-loss limitations. No rollout is performed by the verification gate.
