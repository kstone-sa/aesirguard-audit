# audit2json

audit2json converts Linux Audit records into compact, canonical newline-delimited JSON.

The project is intended to become a persistent, low-latency collector that follows the audit log, assembles multi-record audit events, normalizes Linux-specific values, and writes events to stdout or an append-only file. Its output schema is independent from Splunk CIM, Microsoft Sentinel ASIM, Elastic ECS, and other backend models.

## Current status

The repository currently contains the v0.1 batch parser. It can:

- read stdin or one existing file;
- parse a limited subset of Audit records;
- group records by audit ID;
- reconstruct basic EXECVE and PROCTITLE data;
- emit one compact JSON object per line.

The current implementation exits at EOF and relies mainly on EOE records or final EOF to flush events. Persistent following, complete event-boundary handling, checkpoints, rotation, singleton execution, and file output are planned and are not implemented yet.

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

## Target runtime model

The target process is long-running:

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

## Build the current parser

```bash
go test ./...
go vet ./...
go build -o audit2json ./cmd/audit2json
```

## Run the current parser

Read a sample file:

```bash
./audit2json testdata/audit.log
```

Read stdin:

```bash
cat testdata/audit.log | ./audit2json
```

Write current output to a file:

```bash
./audit2json /var/log/audit/audit.log > audit.json
```

This redirection is batch behavior, not the planned managed file sink.

## Documentation map

- `docs/architecture.md`: component boundaries and target data flow;
- `docs/schema.md`: current schema and canonical-schema principles;
- `docs/reliability.md`: checkpoints, delivery semantics, rotation, and failure handling;
- `docs/development.md`: focused development modes and validation;
- `ROADMAP.md`: implementation order and release gates.

## Repository layout

```text
cmd/audit2json/      command-line program
internal/audit/      current parser and event builder
data/                static mapping data
docs/                architecture, schema, reliability, and development guidance
testdata/            reviewable Linux Audit samples
AGENTS.md             scoped instructions for humans and coding agents
```
