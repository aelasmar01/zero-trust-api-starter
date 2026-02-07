from uuid import uuid4

from fastapi import FastAPI

from src.api.audit import emit_authz_audit_event

app = FastAPI(title="Zero Trust API Starter", version="0.1.0")


@app.get("/healthz")
def healthz() -> dict[str, str]:
    emit_authz_audit_event(
        request_id=str(uuid4()),
        tenant_id="system",
        subject={"sub": "healthcheck", "tenant": "system", "roles": ["system"]},
        action={"method": "GET", "route": "/healthz"},
        decision={"allow": True, "reason": "healthcheck"},
    )
    return {"status": "ok"}
