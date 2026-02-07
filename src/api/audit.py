from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from typing import Any, Mapping


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def build_authz_audit_event(
    request_id: str,
    tenant_id: str,
    subject: Mapping[str, Any],
    action: Mapping[str, Any],
    decision: Mapping[str, Any],
    source_ip: str | None = None,
    user_agent: str | None = None,
) -> dict[str, Any]:
    event: dict[str, Any] = {
        "timestamp": _utc_timestamp(),
        "request_id": request_id,
        "tenant_id": tenant_id,
        "subject": {
            "sub": subject.get("sub", ""),
            "tenant": subject.get("tenant", ""),
            "roles": subject.get("roles", []),
        },
        "action": action,
        "decision": {
            "allow": bool(decision.get("allow", False)),
            "reason": str(decision.get("reason", "")),
        },
    }

    if source_ip:
        event["source_ip"] = source_ip
    if user_agent:
        event["user_agent"] = user_agent

    return event


def emit_audit_event(event: Mapping[str, Any]) -> None:
    print(json.dumps(dict(event), separators=(",", ":")), file=sys.stdout, flush=True)


def emit_authz_audit_event(
    request_id: str,
    tenant_id: str,
    subject: Mapping[str, Any],
    action: Mapping[str, Any],
    decision: Mapping[str, Any],
    source_ip: str | None = None,
    user_agent: str | None = None,
) -> None:
    emit_audit_event(
        build_authz_audit_event(
            request_id=request_id,
            tenant_id=tenant_id,
            subject=subject,
            action=action,
            decision=decision,
            source_ip=source_ip,
            user_agent=user_agent,
        )
    )
