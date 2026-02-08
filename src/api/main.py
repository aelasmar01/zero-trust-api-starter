from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException, Request, status

from src.api.audit import emit_authz_audit_event
from src.api.auth import SubjectContext, get_subject_context
from src.api.db import fetch_resources_for_tenant
from src.api.opa_client import query_opa

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


@app.get("/v1/tenant/{tenant_id}/resource")
def list_tenant_resources(
    tenant_id: str,
    request: Request,
    subject: SubjectContext = Depends(get_subject_context),
) -> list[dict]:
    request_id = str(uuid4())
    action = {"method": "GET", "route": "/v1/tenant/{tenant_id}/resource"}
    subject_dict = {
        "sub": subject.sub,
        "tenant": subject.tenant,
        "roles": subject.roles,
        "attrs": subject.attrs,
    }
    resource = {"tenant": tenant_id, "type": "resource", "attrs": {}}

    opa_input = {
        "subject": subject_dict,
        "request": {"method": request.method, "path": str(request.url.path)},
        "resource": resource,
    }
    decision = query_opa(opa_input)

    emit_authz_audit_event(
        request_id=request_id,
        tenant_id=tenant_id,
        subject=subject_dict,
        action=action,
        decision=decision,
        source_ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )

    if not decision.get("allow", False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"reason": decision.get("reason", "deny")},
        )

    try:
        return fetch_resources_for_tenant(tenant_id=tenant_id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"reason": "database_unavailable"},
        )
