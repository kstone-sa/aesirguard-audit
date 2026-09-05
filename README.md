# audit2json

audit2json converts Linux Audit records into compact, canonical newline-delimited JSON.

It is a persistent, low-latency collector that follows the audit log, assembles multi-record audit events, normalizes Linux-specific values, and writes events to stdout or an append-only file. Its output schema is independent from Splunk CIM, Microsoft Sentinel ASIM, Elastic ECS, and other backend models.

## AI-assisted development

This project was designed and developed by Kstone SA with assistance from OpenAI Codex. AI-assisted changes were reviewed, tested, and accepted by the maintainer, who retains responsibility for the project’s architecture, security, quality, and licensing compliance.

## Current status

The v1.0 implementation is feature-complete and is being held as a release candidate until empirical validation milestone 8B is complete. It provides the canonical converter, CIS-oriented and broader security-event classification, checkpointed rotation-aware collection, synthetic hardening, secure filesystem boundaries, and versioned Linux release packaging. The project can:

- read stdin or one existing file;
- preserve ordered and repeated Audit fields;
- group interleaved records by audit ID with explicit completion metadata;
- reconstruct EXECVE arguments and structured PATH records;
- emit the stable, security-oriented canonical v1.0 schema;
- normalize authentication, account, session, service, audit-daemon, mandatory access-control, anomaly, integrity, and selected kernel-security records;
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
- locate a checkpoint generation among retained numeric rotations such as `audit.log.1`;
- drain rename/create rotations before following the replacement inode;
- preserve pending events and partial physical lines across generations;
- detect same-inode truncation as an explicit source gap;
- reopen a managed output file automatically after rename rotation;
- load strict versioned JSON configuration with command-line overrides;
- emit structured operational diagnostics, counters, and heartbeats on stderr.
- verify generated interleaving, large fragmented EXECVE, sink/checkpoint failure windows, and recovery across many retained generations;
- run bounded fuzz campaigns and a reproducible end-to-end pipeline benchmark in CI.
- reject unsafe configuration and managed-output filesystem targets;
- report embedded build version, commit, and date metadata;
- produce reproducible standalone and systemd Linux amd64/arm64 release archives with SHA-256 checksums.

Batch mode still exits at EOF. Follow mode waits at EOF, recovers through retained uncompressed generations, and follows rename/create rotation. Compressed historical logs are not decoded; if the checkpoint inode is no longer available as an uncompressed file, startup fails explicitly.

See `ROADMAP.md` for delivery order, `docs/performance.md` for the synthetic validation model, and `docs/security-event-coverage.md` for security-relevant Audit families beyond the CIS rule profile.

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

The existing distro-labelled fixtures are synthetic representatives. Empirical validation with captured and sanitized Audit output from Debian, Ubuntu, RHEL, and Oracle Linux is milestone v0.8B and has not yet been completed.

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

Stdout is the default sink for consumers such as a Splunk scripted input. An append-only managed file sink is available for file-monitoring agents and other SIEMs. Backend-specific parsing, data-model mapping, tags, aliases, and dashboards are outside this repository.

## Install

Tagged releases provide two archives per Linux architecture:

- `*_standalone.tar.gz` contains the static binary, example configuration, JSON Schema, license, README, and documentation. It makes no service-manager assumption.
- `*_systemd.tar.gz` contains the same files plus the systemd unit, sysusers, and tmpfiles examples.

Verify the selected archive using `SHA256SUMS`, extract it, and run:

```bash
./audit2json --version
./audit2json --config configs/audit2json.example.json --check-config
```

See `docs/runbook.md` for system installation and least-privilege guidance.

## Build from source

```bash
go test ./...
go vet ./...
go build -o audit2json ./cmd/audit2json
./audit2json --version
```

## Quick start

Read a sample file using canonical v1.0 output:

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

Run the same collector from a validated configuration:

```bash
./audit2json --config /etc/audit2json/config.json --check-config
./audit2json --config /etc/audit2json/config.json
```

See `configs/audit2json.example.json`. Command-line values override the file, which keeps one deployment configuration reusable while allowing bootstrap or diagnostic overrides.

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

Checkpoint updates sync a managed output file before advancing input progress. With stdout, a successful write confirms only that the local pipe accepted the bytes; replay after a crash is therefore expected and delivery remains at-least-once. If the checkpoint inode is not the current input, audit2json searches uncompressed sibling files with the configured basename prefix and drains them in modification-time order. Equal timestamps use conventional numeric suffix order (`.2` before `.1`); non-numeric ties fail closed as ambiguous. If it cannot locate the inode, it fails explicitly instead of skipping to the current file.

For live rename/create rotation, the old descriptor must remain at a stable EOF for `--rotation-drain-interval` (default `500ms`) before the collector switches. Same-inode shrink, including copytruncate, is detected and reported as a gap; automatic continuation is intentionally not claimed lossless.

## Documentation map

- `docs/architecture.md`: component boundaries and target data flow;
- `docs/schema.md`: current schema and canonical-schema principles;
- `docs/cis-coverage.md`: guaranteed CIS Linux audit-family coverage and test matrix;
- `docs/security-event-coverage.md`: additional normalized security-event families and renderer coverage;
- `docs/reliability.md`: checkpoints, delivery semantics, rotation, and failure handling;
- `docs/configuration.md`: versioned JSON fields, validation, and CLI overrides;
- `docs/operations.md`: structured diagnostics, counters, lag, and heartbeat semantics;
- `docs/development.md`: focused development modes and validation;
- `docs/compatibility.md`: runtime, distribution, and rotation compatibility matrix;
- `docs/runbook.md`: installation, monitoring, recovery, upgrade, and rollback;
- `docs/release.md`: tagged build and publication procedure;
- `docs/public-release-checklist.md`: final checks before changing repository visibility and tagging v1.0;
- `schema/audit2json-v1.schema.json`: machine-readable canonical event contract;
- `ROADMAP.md`: implementation order and release gates.

## Contributing and security

See `CONTRIBUTING.md` before proposing changes, especially schema changes. Report vulnerabilities using the private process in `SECURITY.md`, not a public issue. The project is licensed under Apache-2.0; see `LICENSE`.

## Repository layout

```text
cmd/audit2json/      command-line program
internal/audit/      current parser and event builder
data/                embedded static mapping data
configs/             example operational configuration
packaging/systemd/   service, sysusers, and tmpfiles examples
schema/              machine-readable canonical event contract
scripts/             release packaging automation
docs/                architecture, schema, reliability, and development guidance
testdata/            reviewable Linux Audit samples
AGENTS.md             scoped instructions for humans and coding agents
```
