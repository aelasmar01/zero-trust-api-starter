from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass
from typing import Any

from fastapi import Header, HTTPException, status

DEV_JWT_SECRET_ENV = "DEV_JWT_SECRET"
DEV_JWT_ISSUER_ENV = "DEV_JWT_ISSUER"
DEV_JWT_AUDIENCE_ENV = "DEV_JWT_AUDIENCE"


class AuthError(ValueError):
    """Raised when auth header/token validation fails."""


@dataclass(frozen=True)
class SubjectContext:
    sub: str
    tenant: str
    roles: list[str]
    attrs: dict[str, Any]


def _b64url_decode(segment: str) -> bytes:
    pad = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + pad)


def _decode_jwt_parts(token: str) -> tuple[dict[str, Any], dict[str, Any], bytes, bytes]:
    parts = token.split(".")
    if len(parts) != 3:
        raise AuthError("token_format_invalid")

    header_segment, payload_segment, signature_segment = parts
    try:
        header = json.loads(_b64url_decode(header_segment))
        payload = json.loads(_b64url_decode(payload_segment))
        signature = _b64url_decode(signature_segment)
    except Exception as exc:
        raise AuthError("token_decode_failed") from exc

    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise AuthError("token_payload_invalid")

    signing_input = f"{header_segment}.{payload_segment}".encode("ascii")
    return header, payload, signature, signing_input


def _verify_hs256_signature(signing_input: bytes, signature: bytes, secret: str) -> None:
    expected = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    if not hmac.compare_digest(signature, expected):
        raise AuthError("token_signature_invalid")


def _validate_registered_claims(payload: dict[str, Any], issuer: str, audience: str) -> None:
    exp = payload.get("exp")
    if not isinstance(exp, (int, float)):
        raise AuthError("token_missing_exp")
    if int(time.time()) >= int(exp):
        raise AuthError("token_expired")

    if payload.get("iss") != issuer:
        raise AuthError("token_issuer_invalid")

    aud = payload.get("aud")
    if isinstance(aud, str):
        aud_values = [aud]
    elif isinstance(aud, list) and all(isinstance(item, str) for item in aud):
        aud_values = aud
    else:
        raise AuthError("token_audience_invalid")

    if audience not in aud_values:
        raise AuthError("token_audience_mismatch")


def decode_dev_jwt_hs256(token: str, secret: str, issuer: str, audience: str) -> dict[str, Any]:
    header, payload, signature, signing_input = _decode_jwt_parts(token)

    if header.get("alg") != "HS256":
        raise AuthError("token_algorithm_invalid")

    _verify_hs256_signature(signing_input=signing_input, signature=signature, secret=secret)
    _validate_registered_claims(payload=payload, issuer=issuer, audience=audience)
    return payload


def normalize_subject_context(payload: dict[str, Any]) -> SubjectContext:
    sub = payload.get("sub")
    if not isinstance(sub, str) or not sub:
        raise AuthError("token_subject_invalid")

    tenant = payload.get("tenant")
    if not isinstance(tenant, str) or not tenant:
        raise AuthError("token_tenant_invalid")

    raw_roles = payload.get("roles", [])
    if raw_roles is None:
        roles: list[str] = []
    elif isinstance(raw_roles, list) and all(isinstance(role, str) and role for role in raw_roles):
        roles = raw_roles
    else:
        raise AuthError("token_roles_invalid")

    raw_attrs = payload.get("attrs", {})
    if raw_attrs is None:
        attrs: dict[str, Any] = {}
    elif isinstance(raw_attrs, dict):
        attrs = raw_attrs
    else:
        raise AuthError("token_attrs_invalid")

    return SubjectContext(sub=sub, tenant=tenant, roles=roles, attrs=attrs)


def _extract_bearer_token(authorization: str) -> str:
    parts = authorization.strip().split(" ")
    if len(parts) != 2:
        raise AuthError("authorization_header_invalid")

    scheme, token = parts
    if scheme.lower() != "bearer" or not token:
        raise AuthError("authorization_header_invalid")

    return token


def _unauthorized(reason: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=reason,
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_subject_context(authorization: str | None = Header(default=None)) -> SubjectContext:
    """
    Development-only JWT validation using a shared secret (HS256).
    Production should switch to OIDC discovery + JWKS-backed verification.
    """
    if not authorization:
        raise _unauthorized("authorization_header_missing")

    secret = os.getenv(DEV_JWT_SECRET_ENV)
    if not secret:
        raise _unauthorized("dev_jwt_secret_missing")

    issuer = os.getenv(DEV_JWT_ISSUER_ENV, "https://dev-issuer.local")
    audience = os.getenv(DEV_JWT_AUDIENCE_ENV, "zero-trust-api")

    try:
        token = _extract_bearer_token(authorization)
        claims = decode_dev_jwt_hs256(token=token, secret=secret, issuer=issuer, audience=audience)
        return normalize_subject_context(claims)
    except AuthError as exc:
        raise _unauthorized(str(exc)) from exc
