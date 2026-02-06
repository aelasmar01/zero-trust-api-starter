# Threat Model (Placeholder)

## Objective
Define trust boundaries and abuse paths for a multi-tenant API that uses JWT
identity and policy-based authorization.

## In Scope
- API request authentication and subject extraction
- Authorization decisions (RBAC/ABAC)
- Tenant isolation at policy and data-access layers
- Authorization audit event emission

## Out of Scope (for now)
- UI/browser threat modeling
- Full production hardening controls

## Initial Trust Boundaries
- Client <-> API
- API <-> OPA
- API <-> Database
- API <-> Audit sink

## Initial Threat Themes
- Broken access control and tenant breakout
- Token misuse or claim tampering
- Fail-open behavior on dependency errors
- Missing or misleading authorization audit trails
