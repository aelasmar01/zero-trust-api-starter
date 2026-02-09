# Threat Model

## Implemented System
- API: FastAPI service with endpoints:
  - `GET /healthz`
  - `GET /v1/tenant/{tenant_id}/resource`
- Authentication: JWT bearer validation in `src/api/auth.py` (development mode HS256).
- Authorization: OPA policy decision in `src/api/opa_client.py` and `infra/opa/policy.rego`.
- Data access: Postgres query helper in `src/api/db.py` with mandatory tenant predicate.
- Audit: structured JSON authorization events emitted to stdout via `src/api/audit.py`.

## Trust Boundaries
- Client -> API: untrusted request headers and path inputs.
- API -> OPA: policy decision dependency.
- API -> Postgres: tenant-scoped data access dependency.
- API -> Audit output: stdout log stream.

## Security Objectives
- Enforce tenant isolation for all protected resource reads.
- Enforce role and attribute constraints with deny-by-default policy behavior.
- Fail closed on authn/authz dependency failures.
- Emit auditable allow/deny decision records.

## Authorization and Isolation Controls
- JWT checks: signature (`HS256`), `exp`, `iss`, `aud`.
- Subject normalization: `{sub, tenant, roles, attrs}`.
- OPA input includes `subject`, `request`, and `resource` context.
- Rego policy enforces:
  - explicit tenant match
  - RBAC by method/role
  - ABAC hooks (`env`, `data_classification`, `clearance`)
- DB access helper always requires `tenant_id` and applies `WHERE tenant_id = %s`.

## Fail-Closed Behavior
- Missing or invalid token: `401 Unauthorized`.
- OPA deny decision: `403 Forbidden`.
- OPA error/timeout/unreachable: normalized to deny (`403`) by client logic.
- DB failure after allow decision: `503 Service Unavailable` with `database_unavailable`.

## Primary Misuse Cases Covered
- Cross-tenant object access attempts.
- Role escalation attempts.
- ABAC attribute bypass attempts.
- Token tampering and claim abuse.
- Fail-open attempts during PDP or dependency errors.

## Residual Risks (Current Scope)
- JWT verification is development-only shared-secret mode; production OIDC/JWKS is not yet implemented.
- No rate limiting, WAF, or advanced abuse controls in this baseline.
- Audit sink is stdout only; tamper-evident log transport/storage is out of scope.
