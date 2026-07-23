# AGENTS.md

## Project purpose

audit2json converts Linux auditd records into compact JSON events suitable for Splunk ingestion.

## Design rules

- Keep the implementation simple, deterministic, and easy to audit.
- Use the Go standard library only unless a dependency is explicitly approved.
- Do not use CGO.
- Do not depend on libaudit, libauparse, Python, shell tools, or external runtimes.
- Prefer readable code over clever code.
- Keep functions small and focused.
- Avoid regex-heavy parsing.
- Preserve backward compatibility of emitted JSON fields whenever possible.
- Minimize output size. Do not emit empty fields, nulls, or empty arrays.
- Use compact JSON keys documented in `docs/schema.md`.
- Keep source code, comments, documentation, commit messages, and issues in English.

## Testing rules

Before proposing a change, run:

```bash
go test ./...
go vet ./...
```

Add or update tests for parser behavior, event grouping, field normalization, and malformed input.

## Scope boundaries

The parser delivery reads from a file or stdin and writes one JSON object per line to stdout.

The following features belong to later deliveries and must not be mixed into parser changes unless requested:

- log following
- rotation handling
- checkpoints
- timeout-based event flushing
- Splunk TA packaging

## Data files

Static mappings belong under `data/` as JSON. JSON files contain data only; they must not become a configuration language or expression engine.
