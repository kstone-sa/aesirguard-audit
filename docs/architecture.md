# Architecture

## Goal

audit2json reduces Linux auditd verbosity by merging all records that share the same audit ID into one compact JSON event.

## Parser delivery flow

```text
audit.log or stdin
        |
        v
line scanner
        |
        v
record parser
        |
        v
group by audit ID
        |
        v
event builder
        |
        v
JSON encoder
        |
        v
stdout
```

## Components

### `cmd/audit2json`

Command-line entry point. It accepts either stdin or one audit log file and writes newline-delimited JSON to stdout.

### `internal/audit`

Contains the audit line lexer, record parser, event grouping model, and compact event builder.

### `data`

Contains static mappings that may later be loaded by the normalizer. These files contain data only and are intentionally not a rule language.

### `testdata`

Contains small, reviewable audit samples used for manual and automated testing.

## Event boundaries

An audit event normally ends with an `EOE` record. Parser delivery also flushes incomplete events at end-of-file so offline samples can be tested easily.

A later live collector delivery will add timeout-based flushing and log rotation handling.

## Non-goals for parser delivery

- following a growing log file
- persisting checkpoints
- handling log rotation
- acting as a daemon
- exposing a network service
- integrating directly with Splunk APIs
