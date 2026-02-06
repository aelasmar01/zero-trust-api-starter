# Audit Schema (v0 Placeholder)

Authorization decisions emit one structured JSON audit event per request.

## Planned Fields
- `timestamp` (RFC3339)
- `request_id` (UUID)
- `tenant_id`
- `subject.sub`
- `subject.tenant`
- `subject.roles` (array)
- `action` (method + route)
- `decision.allow` (boolean)
- `decision.reason` (string)
- `source_ip` (optional)
- `user_agent` (optional)

## Notes
Field names and constraints will be finalized with implementation.
