# AesirGuard Audit

**Security-oriented Linux Audit normalization without changing the Linux Audit stack.**

AesirGuard Audit turns raw Linux Audit data into compact, canonical JSON events for detection engineering, threat hunting, incident investigation, and compliance monitoring.

It is deliberately non-invasive: AesirGuard Audit can process existing `audit.log` files without replacing `auditd`, installing an audit plugin, or modifying the host's audit pipeline. It can run entirely within the collection layer—for example as part of a Splunk deployment—so security teams can add Linux Audit normalization without introducing another host-level service.

Linux Audit provides rich forensic evidence, but emits fragmented, kernel-centric records whose security meaning is expensive to reconstruct downstream. AesirGuard Audit follows the audit stream, correlates multi-record events, preserves relevant evidence, and normalizes supported process, file, identity and access-control evidence into a stable canonical JSON schema. Additional audit, integrity and kernel-security families receive stable classifications; their field-level normalization varies, as documented in the [coverage matrix](docs/security-event-coverage.md).

The project is deliberately backend-agnostic. Splunk, Microsoft Sentinel, Elastic, and other analytics platforms are consumers of its output; their data models do not define AesirGuard Audit's security semantics.

## AI-assisted development

This project was designed and developed by Kstone SA with assistance from OpenAI Codex. AI-assisted changes were reviewed, tested, and accepted by the maintainer, who retains responsibility for the project’s architecture, security, quality, and licensing compliance.

## Pre-release status

AesirGuard Audit is the new pre-1.0 product name; **v0.10.0 is the intended first
release under this name and has not been published by this pass**. Published
audit2json v0.9.0 and v0.9.1 retain their original names and assets. This branch's
commands use the new naming; see [the migration guide](docs/rebranding.md).
Qualification builds are for controlled evaluation, with no stable distribution
compatibility certification.

The v1.0 implementation is feature-complete, but empirical qualification is incomplete, with initial Ubuntu 24.04 arm64 ENRICHED use now exercised; see [Compatibility](docs/compatibility.md). Until that work is complete, distro-labelled fixtures are synthetic regression data rather than compatibility certification. No stable release is currently supported.

The current `main` branch provides:

- read stdin or one existing file;
- preserve ordered and repeated Audit fields;
- group interleaved records by audit ID with explicit completion metadata;
- reconstruct EXECVE arguments and structured PATH records;
- emit the stable, security-oriented canonical v1.0 schema;
- classify authentication, account, session, service, audit-daemon, mandatory access-control, anomaly, integrity, and selected kernel-security records, with typed evidence as specified in the coverage matrix;
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
- persist a v2 checkpoint with a bounded source-content anchor at complete-line and accepted-output boundaries;
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
- produce reproducible Linux amd64/arm64 release archives with SHA-256 checksums.

Batch mode still exits at EOF. Follow mode waits at EOF, recovers through retained uncompressed generations, and follows rename/create rotation. Compressed historical logs are not decoded; if the checkpoint inode is no longer available as an uncompressed file, startup fails explicitly.

See `ROADMAP.md` for planned validation and future work, `docs/performance.md` for the synthetic validation model, and `docs/security-event-coverage.md` for security-relevant Audit families beyond the CIS rule profile.

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

The targeted CIS semantic rendering is designed for `auditd` configured with `log_format=ENRICHED`. RAW records remain accepted with explicit numeric fallbacks, but classification may be less specific when only architecture-dependent syscall numbers are available. Distribution-specific behavior still requires empirical validation.

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

## Related projects

[LAUREL](https://github.com/threathunters-io/laurel) addresses a closely related problem: it correlates Linux Audit records and emits structured JSON suitable for security analytics. Its normal deployment model integrates with the Linux Audit pipeline as an auditd/audisp-style processor and provides rich process-oriented enrichment.

AesirGuard Audit deliberately takes a different operational approach. It can consume existing `audit.log` files without replacing `auditd`, installing an Audit plugin, or changing the host's Audit pipeline, which allows it to live in an existing collection layer such as a Splunk deployment. It also projects Audit evidence into a compact, backend-agnostic security schema rather than primarily preserving Audit's native record structure.

The projects therefore overlap in the problem they address, but optimize for different deployment and normalization models.

## Installation

The renamed packaging produces two independent archives per Linux architecture:

- `*_standalone.tar.gz` is the portable package. It contains the static binary, example configuration, JSON Schema, license, changelog, and documentation. It makes no service-manager assumption and is the appropriate artifact for Splunk, containers, schedulers, and custom supervisors.
- `*_systemd.tar.gz` is the optional host-service package. It contains the standalone payload plus a hardened systemd unit and its sysusers/tmpfiles definitions.

Verify the selected archive using `SHA256SUMS`, extract it, and run:

```bash
./ag-audit --version
./ag-audit --config configs/aesirguard-audit.example.json --check-config
```

See `docs/runbook.md` for standalone and systemd installation instructions and least-privilege guidance. The supplied service is a deployment option, not a requirement of AesirGuard Audit.

## Build from source

Go 1.26 is the minimum source version. Official CI and release builds use the exact supported toolchain pinned in `.go-version` (currently Go 1.26.8). See [Release verification](docs/release.md) for the full shared quality gate.

```bash
go test ./...
go vet ./...
go build -o ag-audit ./cmd/ag-audit
./ag-audit --version
```

## Quick start

Read a sample file using canonical v1.0 output:

```bash
./ag-audit testdata/execve.audit
```

Read stdin and explicitly include source identity:

```bash
cat /var/log/audit/audit.log | ./ag-audit --source-host host01
```

`source` is omitted by default because the collecting backend commonly supplies host metadata itself.

Rendered messages are optional convenience/debug output. They duplicate canonical fields and should normally remain disabled for volume-sensitive SIEM ingestion. The shipped configuration disables them; explicitly opt in when useful:

```bash
./ag-audit --render-message testdata/execve.audit
```

Write current output to a file:

```bash
./ag-audit /var/log/audit/audit.log > audit.json
```

This redirection is batch behavior, not the managed file sink.

Follow a live Audit log and emit to stdout:

```bash
./ag-audit --follow /var/log/audit/audit.log
```

Run the same collector from a validated configuration:

```bash
./ag-audit --config /etc/aesirguard-audit/config.json --check-config
./ag-audit --config /etc/aesirguard-audit/config.json
```

See `configs/aesirguard-audit.example.json`. Command-line values override the file, which keeps one deployment configuration reusable while allowing bootstrap or diagnostic overrides.

Repeated scheduled invocations are safe: while one healthy process owns the per-input lock, another exits successfully without emitting data.
The default lock is stored in a private per-user temporary directory and is derived from the absolute input path. Use `--lock-file` to place it in a service-managed runtime directory.

Use the managed append-only file sink:

```bash
./ag-audit --follow --output-file /var/log/aesirguard-audit/events.ndjson /var/log/audit/audit.log
```

Add `--sync-output` only when every emitted line must cross the local filesystem durability boundary before processing continues. It deliberately trades throughput for durability.

Enable crash recovery with an explicit durable checkpoint path:

```bash
./ag-audit --follow \
  --checkpoint-file /var/lib/aesirguard-audit/audit.checkpoint \
  --output-file /var/log/aesirguard-audit/events.ndjson \
  /var/log/audit/audit.log
```

Checkpoint updates sync a managed output file before advancing input progress. With stdout, a successful write confirms only that the local pipe accepted the bytes; replay after a crash is therefore expected and delivery remains at-least-once. If the checkpoint inode is not the current input, AesirGuard Audit searches retained uncompressed numeric rotations and drains them in descending numeric suffix order (`.2` before `.1`, then the active file). Missing intermediate generations, duplicate suffix numbers, and inode aliases fail closed; non-numeric siblings are not input generations. If it cannot locate the inode, or its saved content anchor does not match, it fails explicitly instead of skipping to the current file. Checkpoint v1 is rejected; see the runbook for explicit replay migration and the reliability document for the sampled anchor guarantee and limitations.

For live rename/create rotation, the old descriptor must remain at a stable EOF for `--rotation-drain-interval` (default `500ms`) before the collector switches. Same-inode shrink, including copytruncate, is detected and reported as a gap; automatic continuation is intentionally not claimed lossless.

## Documentation map

- `docs/architecture.md`: component boundaries and target data flow;
- `docs/schema.md`: current schema and canonical-schema principles;
- `docs/cis-coverage.md`: targeted CIS Linux audit-family coverage and validation matrix;
- `docs/security-event-coverage.md`: additional normalized security-event families and renderer coverage;
- `docs/reliability.md`: checkpoints, delivery semantics, rotation, and failure handling;
- `docs/configuration.md`: versioned JSON fields, validation, and CLI overrides;
- `docs/operations.md`: structured diagnostics, counters, lag, and heartbeat semantics;
- `docs/development.md`: focused development modes and validation;
- `docs/compatibility.md`: runtime, distribution, and rotation compatibility matrix;
- `docs/runbook.md`: installation, monitoring, recovery, upgrade, and rollback;
- `docs/release.md`: pre-release and stable tagged build/publication procedure;
- `docs/public-release-checklist.md`: public visibility, pre-1.0 qualification, and stable v1.0 gates;
- `schema/aesirguard-audit-v1.schema.json`: machine-readable canonical event contract;
- `ROADMAP.md`: pending validation, release gates, and future work.

## Contributing and security

See `CONTRIBUTING.md` before proposing changes, especially schema changes. Report vulnerabilities using the private process in `SECURITY.md`, not a public issue. The project is licensed under Apache-2.0; see `LICENSE`.

## Repository layout

```text
cmd/ag-audit/        command-line program
internal/audit/      current parser and event builder
data/                embedded static mapping data
configs/             example operational configuration
packaging/systemd/   optional host-service deployment files
schema/              machine-readable canonical event contract
scripts/             release packaging automation
docs/                architecture, schema, reliability, and development guidance
testdata/            reviewable Linux Audit samples
AGENTS.md             scoped instructions for humans and coding agents
```
