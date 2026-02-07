# Audit Schema (v0)

Authorization decisions emit one structured JSON event to stdout.

## Event type
- One event per authorization decision (`allow` and `deny`).
- JSON object, single line for log aggregation.

## Required fields
- `timestamp`: RFC3339 UTC timestamp
- `request_id`: UUID generated per request
- `tenant_id`: resolved tenant id used for evaluation
- `subject.sub`: subject/user id
- `subject.tenant`: tenant claim from subject context
- `subject.roles`: role list used in decision
- `action`: object describing attempted action (for example `method` and `route`)
- `decision.allow`: boolean authorization outcome
- `decision.reason`: stable policy reason string

## Optional fields
- `source_ip`
- `user_agent`

## Example
```json
{
  "timestamp": "2026-02-07T10:15:30.123456Z",
  "request_id": "3f0b2de2-a3f4-46dc-b8e8-a939613fdb61",
  "tenant_id": "tenant-a",
  "subject": {
    "sub": "user-123",
    "tenant": "tenant-a",
    "roles": ["reader"]
  },
  "action": {
    "method": "GET",
    "route": "/v1/tenant/tenant-a/resource"
  },
  "decision": {
    "allow": true,
    "reason": "allow_tenant_read"
  },
  "source_ip": "203.0.113.10",
  "user_agent": "curl/8.0"
}
```
