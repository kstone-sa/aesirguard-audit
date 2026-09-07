# Contributing to audit2json

Thank you for helping improve audit2json. Keep changes small, reviewable, and independent from any SIEM backend.

## Before opening a change

- Open an issue before changing the canonical event schema, checkpoint format, delivery guarantees, or supported input behavior.
- Do not submit real Audit logs unless they have been deliberately sanitized. Remove hostnames, account names, addresses, paths, rule keys, identifiers, and embedded user-space payloads that could identify an environment.
- Keep backend-specific mappings and detections outside the core canonical model.
- Add mapping data as reviewable JSON instead of introducing an expression language.

## AI-assisted and agentic development

AI-assisted development is welcome, including coding agents, provided the human contributor remains responsible for the submitted change.

- Read and follow `AGENTS.md` before using an agent on this repository. Its scope, architectural boundaries, status guardrails, and validation rules apply equally to human-authored and agent-authored changes.
- Review all generated code, tests, documentation, configuration, and commit content before submission. Do not treat generated output or an agent's successful completion message as verification.
- Run the same required validation for AI-assisted changes as for manually written changes. Generated tests must exercise the intended invariant rather than merely reproduce the implementation.
- Keep agent work narrowly scoped. Do not use an agent to perform broad refactors, dependency changes, schema migrations, history rewrites, release publication, or security-boundary changes unless those actions are explicitly part of the reviewed task.
- Do not weaken, bypass, remove, or rewrite CI, security checks, release verification, compatibility gates, or fail-closed behavior merely to make a generated change pass.
- Never provide agents or external AI services with secrets, credentials, customer data, production Audit logs, identifying infrastructure details, or other material that is not appropriate for disclosure to that service.
- Preserve provenance when it matters to review. If AI assistance materially shaped a pull request, mention it briefly in the pull-request description together with the human verification performed.
- The contributor who submits the change is accountable for its correctness, security, licensing, and compatibility impact regardless of which tools were used to produce it.

The repository itself may use AI-assisted development, but no AI system is treated as an author, approver, security authority, or substitute for maintainer review.

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
