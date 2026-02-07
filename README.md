# zero-trust-api-starterkit

Starter kit for demonstrating secure, verifiable API authorization in a multi-tenant REST API.

## Scope
- FastAPI API surface
- OIDC/JWT-based authentication
- Tenant-scoped RBAC/ABAC authorization via OPA/Rego
- Structured audit events for authorization decisions
- Security-focused authorization tests

## Authentication (current state)
- The current implementation uses development-only JWT validation with shared-secret HS256.
- `Authorization: Bearer <JWT>` is required.
- Required checks in dev mode: signature (`HS256`), `exp`, `iss`, and `aud`.
- Subject context is normalized to:
  - `sub` (user id)
  - `tenant` (tenant claim)
  - `roles` (list of role strings)
  - `attrs` (attribute dictionary)

### Dev auth environment variables
- `DEV_JWT_SECRET` (required)
- `DEV_JWT_ISSUER` (optional, default: `https://dev-issuer.local`)
- `DEV_JWT_AUDIENCE` (optional, default: `zero-trust-api`)

### Important
This validation path is for local/dev scaffolding only. Production should use OIDC discovery and JWKS-based key verification.

## Status
Repository scaffold and high-level documentation placeholders are in place.
