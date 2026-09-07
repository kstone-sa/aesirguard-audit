# Development workflow

## Goal

Keep changes focused, reviewable, and cheap to reason about. The repository is intentionally small; development should not require loading every document and package into context.

`AGENTS.md` is the entry point and routing table.

## Work modes

### Documentation mode

Read the requested document, `AGENTS.md`, and only directly linked material needed for consistency.

Allowed changes:

- Markdown documentation;
- roadmap and status wording;
- contributor instructions.

Do not modify Go, mappings, fixtures, or generated artifacts.

### Parser correctness mode

Read:

- `docs/schema.md`;
- `internal/audit/parser.go`;
- directly relevant parser tests and fixtures.

Focus on one grammar, event-boundary, or assembly behavior at a time. Do not add collection, checkpoint, rotation, or backend behavior in the same change.

### Schema and translation mode

Read:

- `docs/schema.md`;
- only the mapping files and handlers involved in the requested event family;
- matching tests and fixtures.

Keep source and normalized values distinguishable. Do not introduce Splunk CIM, Sentinel ASIM, Elastic ECS, detections, or backend transport behavior.

Human-readable messages are optional derived output and require deterministic tests.

### Collector and recovery mode

Read:

- `docs/architecture.md`;
- `docs/reliability.md`;
- only collector, sink, checkpoint, and command files involved in the change.

Keep parsing and normalization APIs stable unless the task explicitly spans that boundary. Implement following, checkpointing, and rotation as separate components even if they are released together.

### Performance and release mode

Read only the affected implementation, benchmarks, release instructions, and compatibility documentation.

Do not optimize without a reproducible benchmark. Do not change schema semantics as a performance optimization.

## Change workflow

1. State the work mode and exact invariant being changed.
2. Confirm whether the referenced behavior is current or planned.
3. Read only the routed files.
4. Make the smallest coherent change.
5. Add focused tests and fixtures.
6. Run the validation required by `AGENTS.md`.
7. Update only documentation whose contract changed.
8. Report limitations and unverified assumptions.

Avoid broad cleanup, renaming, or formatting in functional changes.

## Test strategy

Prefer small fixtures that demonstrate one behavior, plus golden events for complete record families.

Coverage priorities:

- repeated and nested fields;
- quoted values, literal backslashes, hexadecimal encodings, and malformed values;
- interleaved and out-of-order records;
- EOE, terminal, single-record, watermark, and timeout completion;
- long and fragmented EXECVE;
- repeated PATH records with metadata;
- checkpoint crash windows;
- rename/create and truncation rotation;
- slow or failed sinks;
- bounded-memory behavior;
- deterministic output.

Fuzz the record lexer and state transitions once their contracts are stable.

## Documentation discipline

Always distinguish:

- implemented behavior;
- accepted design;
- future proposal.

Do not copy the same detailed invariant into multiple files. Use:

- `README.md` for orientation and current status;
- `ROADMAP.md` for pending validation, release gates, and future work;
- `docs/architecture.md` for component ownership;
- `docs/schema.md` for event contracts;
- `docs/reliability.md` for recovery and delivery invariants;
- this file for contributor workflow.

## Commit discipline

Use one conceptual change per commit. Documentation-only planning should not contain code changes. Functional commits should name the affected boundary, such as parser, assembler, collector, checkpoint, rotation, mapping, renderer, or sink.

## Schema validation tooling

The collector runtime remains Go and standard-library-only. CI uses Python's `jsonschema==4.26.0` exclusively as an independent development validator in a disposable virtual environment. Build the binary, then run `python3 scripts/validate-schema.py /absolute/path/to/audit2json` from an environment with that validator installed. It validates all emitted fixture events against Draft 2020-12, exercises the exceptional byte and seccomp fields, and checks negative contracts. It is not part of runtime deployment or release archives.

## Source compatibility and release toolchain

`go.mod` declares **Go 1.26** as the minimum source language compatibility for the current development line.

`.go-version` pins **1.26.8** for CI and release builds. It is a supported, patched release listed by [Go downloads](https://go.dev/dl/) and the [release history](https://go.dev/doc/devel/release). Updating either the minimum source version or the release-toolchain pin is a deliberate reviewed maintenance change; recheck support and security advisories before every tagged release. Package builds reject other toolchains and disable automatic toolchain selection, workspace overrides, custom GOFLAGS/GOEXPERIMENT and CPU tuning. Archive metadata is normalized. `BUILD-INFO.json` records the actual toolchain, source commit, version, build date, architecture and binary digest; the binary's `--version` exposes the same release identity. No toolchain is bundled at runtime.

The full shared CI/tag gate is `scripts/verify-all.sh`; see [Release](release.md) for invocation. It also runs `govulncheck` v1.7.0 against the live vulnerability database. This tool and its module dependencies are development-only and do not enter the collector's `go.mod` or release runtime.
