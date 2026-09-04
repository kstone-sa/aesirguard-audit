# Performance and synthetic regression

## Scope

Milestone v0.8A measures and stresses the in-process parser, assembler, canonical normalizer, optional renderer, JSON encoding, sinks, checkpoints, and rotating follower. It is designed to expose correctness failures before optimization.

The benchmark is not a capacity promise for a production host. Filesystem, kernel, audit backlog, pipe consumer, storage durability, and SIEM ingestion behavior remain deployment variables.

## Automated coverage

Normal CI runs deterministic tests, the Go race detector, and vet. A separate synthetic job runs bounded parser and assembler fuzz campaigns and exercises the end-to-end benchmark with allocation reporting.

The generated tests assert:

- accepted assembler records are conserved through completion or final flush;
- repeated input produces deterministic assembly;
- pending events and bytes return to zero after flush;
- fragmented EXECVE arguments preserve ordering and content;
- a failed sink cannot be counted as an emitted event;
- a failed sink commit cannot advance or create a checkpoint;
- recovery traverses a long retained sequence in source order.

## Reproducible benchmark

```bash
go test ./internal/audit -run '^$' -bench '^BenchmarkAuditPipeline$' -benchtime=3s -benchmem
```

The benchmark reports source bytes per second, time per event, bytes allocated, and allocations. Compare results only on the same Go version, architecture, power policy, and otherwise idle host.

CPU and heap profiles can be captured with:

```bash
go test ./internal/audit -run '^$' -bench '^BenchmarkAuditPipeline$' -benchtime=10s -cpuprofile=cpu.out -memprofile=mem.out
go tool pprof cpu.out
go tool pprof mem.out
```

Generated profiles are local artifacts and must not be committed.

## Deliberate limitation

Synthetic records cannot prove that a distribution emits the assumed field names, record families, ordering, or ENRICHED interpretations. Milestone v0.8B requires sanitized captures from the exact supported distribution, kernel, auditd, and CIS rule versions. Its completion remains explicitly pending.
