from __future__ import annotations

import json
import os
import socket
from dataclasses import dataclass
from typing import Any, Mapping
from urllib import error, request

OPA_URL_ENV = "OPA_URL"
OPA_TIMEOUT_SECONDS_ENV = "OPA_TIMEOUT_SECONDS"
DEFAULT_OPA_URL = "http://localhost:8181/v1/data/authz/decision"
DEFAULT_TIMEOUT_SECONDS = 2.0


@dataclass(frozen=True)
class OpaDecision:
    allow: bool
    reason: str

    def as_dict(self) -> dict[str, Any]:
        return {"allow": self.allow, "reason": self.reason}


def _deny(reason: str) -> OpaDecision:
    return OpaDecision(allow=False, reason=reason)


def _resolve_opa_url() -> str:
    url = os.getenv(OPA_URL_ENV, DEFAULT_OPA_URL).strip()
    if url.endswith("/"):
        url = url.rstrip("/")
    if url.endswith("/v1/data/authz"):
        url = f"{url}/decision"
    return url


def _resolve_timeout_seconds() -> float:
    raw_value = os.getenv(OPA_TIMEOUT_SECONDS_ENV, str(DEFAULT_TIMEOUT_SECONDS))
    try:
        parsed = float(raw_value)
    except (TypeError, ValueError):
        return DEFAULT_TIMEOUT_SECONDS
    if parsed <= 0:
        return DEFAULT_TIMEOUT_SECONDS
    return parsed


def normalize_opa_decision(response_payload: Mapping[str, Any]) -> dict[str, Any]:
    result = response_payload.get("result")
    if not isinstance(result, Mapping):
        return _deny("deny_opa_result_missing").as_dict()

    nested_decision = result.get("decision")
    decision_payload = nested_decision if isinstance(nested_decision, Mapping) else result

    allow_value = decision_payload.get("allow")
    reason_value = decision_payload.get("reason")

    if not isinstance(allow_value, bool):
        return _deny("deny_opa_result_invalid_allow").as_dict()

    if isinstance(reason_value, str) and reason_value:
        reason = reason_value
    else:
        reason = "allow" if allow_value else "deny"

    return OpaDecision(allow=allow_value, reason=reason).as_dict()


def query_opa(
    input_document: Mapping[str, Any],
    opa_url: str | None = None,
    timeout_seconds: float | None = None,
) -> dict[str, Any]:
    """
    Expected OPA input document shape:
      {
        "subject": {
          "sub": str,
          "tenant": str,
          "roles": [str],
          "attrs": {
            "env": str,                  # optional ABAC attribute
            "clearance": str,            # optional, e.g. internal/restricted
            ...
          }
        },
        "request": {
          "method": str,                 # GET/POST/DELETE...
          "path": str
        },
        "resource": {
          "tenant": str,
          "type": str,
          "attrs": {
            "env": str,                  # optional ABAC guard
            "data_classification": str,  # optional, e.g. internal/restricted
            ...
          }
        }
      }
    """
    resolved_url = (opa_url or _resolve_opa_url()).strip()
    resolved_timeout = timeout_seconds if timeout_seconds is not None else _resolve_timeout_seconds()

    request_body = json.dumps({"input": dict(input_document)}, separators=(",", ":")).encode("utf-8")
    http_request = request.Request(
        resolved_url,
        data=request_body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with request.urlopen(http_request, timeout=resolved_timeout) as response:
            status_code = getattr(response, "status", 200)
            response_body = response.read()
    except error.HTTPError as exc:
        return _deny(f"deny_opa_http_{exc.code}").as_dict()
    except error.URLError as exc:
        if isinstance(exc.reason, socket.timeout):
            return _deny("deny_opa_timeout").as_dict()
        return _deny("deny_opa_unreachable").as_dict()
    except TimeoutError:
        return _deny("deny_opa_timeout").as_dict()
    except Exception:
        return _deny("deny_opa_error").as_dict()

    if status_code < 200 or status_code >= 300:
        return _deny(f"deny_opa_http_{status_code}").as_dict()

    try:
        decoded_payload = json.loads(response_body.decode("utf-8")) if response_body else {}
    except Exception:
        return _deny("deny_opa_response_invalid_json").as_dict()

    if not isinstance(decoded_payload, Mapping):
        return _deny("deny_opa_response_invalid_shape").as_dict()

    return normalize_opa_decision(decoded_payload)
