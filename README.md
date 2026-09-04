# audit2json

audit2json converts Linux Audit records into compact, canonical newline-delimited JSON.

The project is intended to become a persistent, low-latency collector that follows the audit log, assembles multi-record audit events, normalizes Linux-specific values, and writes events to stdout or an append-only file. Its output schema is independent from Splunk CIM, Microsoft Sentinel ASIM, Elastic ECS, and other backend models.

## Current status

The milestone v0.5 development branch contains the canonical converter, CIS-oriented semantic classifier, persistent collector, and opt-in crash recovery. It can:

- read stdin or one existing file;
- preserve ordered and repeated Audit fields;
- group interleaved records by audit ID with explicit completion metadata;
- reconstruct EXECVE arguments and structured PATH records;
- emit one security-oriented canonical v0.3 schema;
- prefer names supplied by Audit ENRICHED records and fall back to explicit ID fields;
- collapse identical login, real, and effective identities;
- decode non-empty file capability masks to Linux capability names;
- classify the Linux Audit activity families covered by the selected CIS Linux server baselines;
- optionally add deterministic analyst-readable messages for those families.
- follow one growing audit file with configurable low-latency polling;
- preserve incomplete physical lines until their newline arrives;
- apply explicit bounds to line and unresolved-event state;
- write synchronously to stdout or an append-only managed file;
- stop cleanly on SIGINT or SIGTERM;
- enforce a non-blocking singleton lock per followed input.
- persist a versioned checkpoint at complete-line and accepted-output boundaries;
- resume the same file generation with at-least-once delivery.

Batch mode still exits at EOF. Follow mode waits at EOF and can recover from a configured checkpoint, but it does not yet locate a rotated checkpoint generation or switch to a new inode. Rotation handling belongs to milestone v0.6.

See `ROADMAP.md` for delivery order.

## Design goals

- native Go;
- standard library only;
- no CGO, Python, libaudit, libauparse, or external runtime;
- one canonical event per line;
- SIEM-agnostic output;
- low latency and bounded memory;
- at-least-once recovery with minimal duplicates;
- lossless processing while the retained source files remain readable;
- deterministic behavior and explicit failure reporting;
- compact output suitable for licensed-volume ingestion.

Guaranteed CIS semantic rendering assumes `auditd` is configured with `log_format=ENRICHED`. RAW records remain accepted with explicit numeric fallbacks, but classification may be less specific when only architecture-dependent syscall numbers are available.

## Target runtime model

```text
audit.log
    -> file follower
    -> record parser
    -> event assembler
    -> normalizer/classifier
    -> optional human renderer
    -> stdout or file sink
```

Stdout is the default sink for consumers such as a Splunk scripted input. An append-only file sink is planned for file-monitoring agents and other SIEMs. Backend-specific parsing, data-model mapping, tags, aliases, and dashboards are outside this repository.

## Build the current converter

```bash
go test ./...
go vet ./...
go build -o audit2json ./cmd/audit2json
```

## Run the current converter

Read a sample file using canonical v0.3 output:

```bash
./audit2json testdata/execve.audit
```

Read stdin and explicitly include source identity:

```bash
cat /var/log/audit/audit.log | ./audit2json --source-host host01
```

`source` is omitted by default because the collecting backend commonly supplies host metadata itself.

Include the optional analyst-readable message:

```bash
./audit2json --render-message testdata/execve.audit
```

Write current output to a file:

```bash
./audit2json /var/log/audit/audit.log > audit.json
```

This redirection is batch behavior, not the managed file sink.

Follow a live Audit log and emit to stdout:

```bash
./audit2json --follow --render-message /var/log/audit/audit.log
```

Repeated scheduled invocations are safe: while one healthy process owns the per-input lock, another exits successfully without emitting data.
The default lock is stored in a private per-user temporary directory and is derived from the absolute input path. Use `--lock-file` to place it in a service-managed runtime directory.

Use the managed append-only file sink:

```bash
./audit2json --follow --output-file /var/log/audit2json/events.ndjson /var/log/audit/audit.log
```

Add `--sync-output` only when every emitted line must cross the local filesystem durability boundary before processing continues. It deliberately trades throughput for durability.

Enable crash recovery with an explicit durable checkpoint path:

```bash
./audit2json --follow \
  --checkpoint-file /var/lib/audit2json/audit.checkpoint \
  --output-file /var/log/audit2json/events.ndjson \
  /var/log/audit/audit.log
```

Checkpoint updates sync a managed output file before advancing input progress. With stdout, a successful write confirms only that the local pipe accepted the bytes; replay after a crash is therefore expected and delivery remains at-least-once. If the checkpoint inode no longer matches the configured input path, v0.5 fails explicitly instead of skipping to the current file.

## Documentation map

- `docs/architecture.md`: component boundaries and target data flow;
- `docs/schema.md`: current schema and canonical-schema principles;
- `docs/cis-coverage.md`: guaranteed CIS Linux audit-family coverage and test matrix;
- `docs/reliability.md`: checkpoints, delivery semantics, rotation, and failure handling;
- `docs/development.md`: focused development modes and validation;
- `ROADMAP.md`: implementation order and release gates.

## Repository layout

```text
cmd/audit2json/      command-line program
internal/audit/      current parser and event builder
data/                embedded static mapping data
docs/                architecture, schema, reliability, and development guidance
testdata/            reviewable Linux Audit samples
AGENTS.md             scoped instructions for humans and coding agents
```
