# audit2json

audit2json converts verbose Linux auditd records into compact newline-delimited JSON suitable for Splunk ingestion.

The project is intentionally small and self-contained:

- pure Go
- standard library only
- no CGO
- no Python
- no libaudit or libauparse
- no daemon and no network service

## Parser delivery

The first delivery reads audit records from stdin or from one file, groups records by audit ID, and emits one compact JSON object per event.

## Offline transfer

For an isolated environment, copy the entire repository tree to the target system. No Internet access is required after Go has been installed.

Required files for parser delivery:

```text
cmd/audit2json/main.go
internal/audit/parser.go
internal/audit/parser_test.go
testdata/audit.log
data/mappings.json
data/syscalls.json
go.mod
```

Documentation files are not required for compilation but should be transferred with the source.

## Build

From the repository root:

```bash
go test ./...
go vet ./...
go build -o audit2json ./cmd/audit2json
```

## Run

Read a sample file:

```bash
./audit2json testdata/audit.log
```

Read stdin:

```bash
cat testdata/audit.log | ./audit2json
```

Write output to a file:

```bash
./audit2json /var/log/audit/audit.log > audit.json
```

The parser delivery processes existing input and exits. Continuous log following, rotation handling, checkpoints, and timeout flushing belong to later deliveries.

## Repository layout

```text
cmd/audit2json/      command-line program
internal/audit/      parser and event builder
data/                static JSON mappings
docs/                architecture and schema documentation
testdata/            small audit samples
AGENTS.md             maintenance rules for humans and AI agents
```

## Output

Output uses compact keys and omits empty fields. See `docs/schema.md`.
