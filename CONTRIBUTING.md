# Contributing to audit2json

Thank you for helping improve audit2json. Keep changes small, reviewable, and independent from any SIEM backend.

## Before opening a change

- Open an issue before changing the canonical event schema, checkpoint format, delivery guarantees, or supported input behavior.
- Do not submit real Audit logs unless they have been deliberately sanitized. Remove hostnames, account names, addresses, paths, rule keys, identifiers, and embedded user-space payloads that could identify an environment.
- Keep backend-specific mappings and detections outside the core canonical model.
- Add mapping data as reviewable JSON instead of introducing an expression language.

## Development

The project requires the Go version declared in `go.mod` and uses the standard library only.

```bash
gofmt -w <changed-go-files>
go test ./...
go test -race ./...
go vet ./...
```

Run focused fuzzing and benchmarks as described in `docs/development.md` when changing parsing, assembly, or performance-sensitive paths. Update the relevant documentation whenever an invariant, output field, or operational guarantee changes.

## Pull requests

Explain the problem, the compatibility impact, and how the change was verified. Include focused regression tests for behavior changes. Do not mix unrelated parser, collector, checkpoint, rotation, and packaging changes in one pull request.

By contributing, you agree that your contribution is licensed under the Apache License 2.0 used by this repository.
