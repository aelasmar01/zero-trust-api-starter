# zero-trust-api-starterkit

Starter kit for demonstrating a secure, testable API authorization model suitable for AppSec ownership.

## What this repo is for
The goal is to build a small multi-tenant REST API that:
- Authenticates requests using OIDC/JWT
- Enforces tenant-scoped authorization (RBAC/ABAC) via OPA/Rego policies
- Emits structured audit events for authorization decisions
- Validates negative cases (broken access control) with a focused test suite

This is an initial scaffold repo. Implementation will be built incrementally.

## Target architecture (planned)
- API middleware: authentication + request context
- Policy Decision Point: OPA (Rego policies)
- Data access layer: tenant filters enforced consistently
- Audit logging: structured events capturing authn/authz context and decisions
- CI: runs policy checks + security-focused authorization tests

## Planned repo artifacts
- Threat model (docs/threat-model.md)
- Sequence diagram (docs/sequence-diagram.*)
- OPA policy files (infra/opa/*)
- Authorization test suite (≥30 cases) + coverage report
- Audit log schema + sample logs
- Misuse catalog mapped to OWASP (docs/misuse-catalog.md)
- Demo script to reproduce key flows

## Success criteria (planned)
- Tenant-scoped RBAC/ABAC test suite with ≥30 authorization cases
- Negative tests proving broken-access-control scenarios are blocked
- Coverage reporting for authz logic and policy paths
- Structured audit events with a documented schema
- Misuse catalog mapping scenarios to OWASP guidance

## Status
Initial commit: repository scaffold + documentation placeholders.
