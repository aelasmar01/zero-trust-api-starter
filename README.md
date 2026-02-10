# Zero Trust API Starter — Policy‑Driven Authorization with JWT + OPA

## Executive Summary

This project demonstrates a Zero Trust API authorization architecture using JWT identity claims and Open Policy Agent (OPA). Every API request is authenticated, tenant‑scoped, and evaluated against externalized authorization policy before access is granted.

The design separates authentication from authorization and removes embedded authorization logic from application code. Instead of trusting network location or implicit roles, every request must present verifiable identity context and pass an explicit policy decision.

This model reduces the risk of privilege escalation, cross‑tenant data exposure, and authorization bypass caused by scattered in‑code role checks. It also enables centralized policy review, safer policy changes, and auditable authorization decisions.

---

## Threat Model

| Threat | Control |
|---------|-----------|
| Token reuse | JWT expiration, issuer, and audience validation |
| Forged tokens | Signature verification with trusted key |
| Cross‑tenant data access | Tenant claim enforced in OPA policy |
| Role escalation | Policy‑based RBAC checks in Rego |
| Policy drift | Externalized Rego policy versioned with code |
| Hidden auth logic | Central policy decision point (OPA) |
| Authorization bypass | Deny‑by‑default policy model |
| Inconsistent access checks | Single structured authorization input |

This threat model reflects common API authorization failure modes seen in multi‑tenant and microservice architectures.

---

## Architecture Overview

Request authorization follows a policy decision pipeline rather than inline role checks.

Client → JWT → FastAPI → Context Extraction → OPA Policy Check → Allow / Deny → API Response

### Step Flow

1. Client sends request with JWT access token
2. FastAPI validates token signature and core claims
3. Identity and request context are extracted
4. Structured authorization input is built
5. Input is sent to OPA policy engine
6. OPA evaluates Rego policy rules
7. Decision returned to API (allow or deny)
8. API returns response or authorization error

---

## Why Authentication Is Not Authorization

Authentication verifies who the caller is.
Authorization determines what the caller is allowed to do.

Many insecure APIs stop at token validation and assume role claims are sufficient. This design enforces a second, explicit authorization decision using external policy so access rules are consistent and testable.

---

## Why Policy Is Externalized

Authorization logic embedded in application code leads to:

• duplicated checks across routes
• inconsistent role handling
• difficult audits
• risky code changes for policy updates

Externalizing policy into OPA provides:

• centralized decision logic
• policy version control
• independent testing of authorization rules
• safer policy iteration without rewriting handlers

---

## Why Tenant Context Is Required

Multi‑tenant APIs must assume hostile tenants. Identity alone is not sufficient — tenant scope must be enforced at authorization time.

OPA policy evaluates tenant identifiers from the token and request context to ensure callers cannot access resources outside their assigned tenant boundary.

This prevents cross‑tenant data exposure caused by missing or inconsistent tenant filters.

---

## Authorization Decision Auditability

Authorization decisions are built from structured input and evaluated by a deterministic policy engine.

This enables:

• reproducible authorization tests
• decision logging
• policy simulation
• traceable allow / deny outcomes
• easier security reviews

Policy becomes inspectable security logic instead of hidden conditional code.

---

## Security Controls Implemented

• JWT signature verification
• Issuer claim validation
• Audience claim validation
• Token expiration enforcement
• Structured identity claim extraction
• Tenant isolation enforced at policy layer
• Role‑based authorization via Rego rules
• External policy decision point (OPA)
• Deny‑by‑default authorization model
• Explicit authorization input schema
• No inline authorization shortcuts in route handlers
• Policy‑driven allow / deny responses

---

## Authorization Input Example

The API builds a structured authorization input document sent to OPA. Example shape:

```
{
  "subject": {
    "user_id": "123",
    "role": "admin",
    "tenant": "tenant_a"
  },
  "action": "read",
  "resource": "invoice",
  "tenant": "tenant_a"
}
```

This structure makes authorization rules explicit, testable, and consistent across endpoints.

---

## Design Principles Demonstrated

• Zero Trust request evaluation
• Policy‑as‑code authorization
• Separation of authN and authZ
• Tenant‑aware access control
• Centralized decision enforcement
• Deny by default
• Security logic externalization
• Audit‑friendly authorization pipeline

---

## Portfolio Review Notes

This project is intended to demonstrate practical AppSec and security engineering patterns:

• Zero Trust authorization design
• Policy‑based access control
• OPA integration with application services
• Multi‑tenant authorization safeguards
• Security control traceability
• Threat‑driven design decisions

Reviewers can evaluate policy logic independently from application code, which mirrors real enterprise authorization architectures.

