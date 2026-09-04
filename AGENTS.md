# AGENTS.md

## Purpose

audit2json converts Linux Audit records into compact, canonical newline-delimited JSON. The core must remain independent from Splunk, Sentinel, Elastic, and every other backend.

## Context budget

Start here, then load only the files routed for the current work mode. Do not read every document or source file by default.

| Work mode | Required context | Allowed scope |
|---|---|---|
| Documentation | The requested document and directly linked documents | Markdown only |
| Parser correctness | `docs/schema.md`, `internal/audit/parser.go`, relevant tests | Record parsing and event assembly |
| Schema and translation | `docs/schema.md`, relevant files under `data/` | Canonical fields, mappings, optional rendering |
| Collector and recovery | `docs/architecture.md`, `docs/reliability.md`, command entry point | Following, checkpoints, rotation, sinks |
| Performance and release | `docs/development.md`, affected packages and tests | Benchmarks, hardening, packaging |

Inspect additional files only when an observed dependency requires them.

## Status guardrail

The milestone v0.6 branch adds retained-generation recovery, live rename/create input rotation, explicit same-inode truncation errors, and automatic managed-output reopen to the checkpointed persistent collector. Broader operational configuration and telemetry remain planned. Never describe a planned capability as implemented.

## Design rules

- Use Go and the standard library only unless a dependency is explicitly approved.
- Do not use CGO, libaudit, libauparse, Python, shell parsers, or external runtimes.
- Keep parsing, assembly, normalization, rendering, collection, and output as separate responsibilities.
- Preserve security-relevant source semantics before compacting data.
- Emit stable field types and omit empty fields, nulls, and empty arrays.
- Keep the canonical schema SIEM-agnostic. Backend schemas belong in backend adapters.
- Treat human-readable messages as optional derived data, never as the source of truth.
- Prefer deterministic, readable code over clever code or regex-heavy parsing.
- Send event data to stdout or the configured file sink. Send diagnostics only to stderr.
- Do not silently discard malformed or unsupported records.
- Keep source, comments, documentation, commit messages, and issues in English.

## Change discipline

- Keep each change inside one work mode whenever possible.
- Do not modify code during documentation-only work.
- Do not combine parser, collector, checkpoint, rotation, and backend integration changes in one patch.
- Preserve emitted fields unless a documented schema migration explicitly changes them.
- Add data mappings as JSON data, not as a configuration or expression language.
- Update the relevant document when an invariant or delivery guarantee changes.

## Validation

For Go changes, run:

```bash
gofmt -w <changed-go-files>
go test ./...
go vet ./...
```

Add focused tests for the changed behavior. Documentation-only changes require link, terminology, current-versus-planned, and cross-document consistency checks; they do not require Go tools.

See `docs/development.md` for the full workflow.
