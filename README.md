# audit2json

audit2json converts Linux Audit records into compact, canonical newline-delimited JSON.

The project is intended to become a persistent, low-latency collector that follows the audit log, assembles multi-record audit events, normalizes Linux-specific values, and writes events to stdout or an append-only file. Its output schema is independent from Splunk CIM, Microsoft Sentinel ASIM, Elastic ECS, and other backend models.

## Current status

The milestone v0.3 development branch contains the batch converter and CIS-oriented semantic classifier. It can:

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

The current implementation still exits at EOF. Broader event-family mappings and rendering, persistent following, checkpoints, rotation, singleton execution, and managed file output are planned and are not implemented yet.

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

This redirection is batch behavior, not the planned managed file sink.

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
