import base64
import hashlib
import hmac
import json
import time
from collections.abc import Generator
from typing import Any

import pytest
from fastapi.testclient import TestClient

from src.api.main import app


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def make_dev_hs256_token(
    *,
    secret: str,
    sub: str = "user-1",
    tenant: str = "tenant-a",
    roles: list[str] | None = None,
    attrs: dict[str, Any] | None = None,
    issuer: str = "https://dev-issuer.local",
    audience: str = "zero-trust-api",
    expires_in_seconds: int = 3600,
) -> str:
    payload = {
        "sub": sub,
        "tenant": tenant,
        "roles": roles or ["reader"],
        "attrs": attrs or {},
        "iss": issuer,
        "aud": audience,
        "exp": int(time.time()) + expires_in_seconds,
    }
    header = {"alg": "HS256", "typ": "JWT"}

    header_segment = _b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_segment = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{header_segment}.{payload_segment}".encode("ascii")
    signature = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    signature_segment = _b64url_encode(signature)

    return f"{header_segment}.{payload_segment}.{signature_segment}"


@pytest.fixture()
def client(monkeypatch: pytest.MonkeyPatch) -> Generator[TestClient, None, None]:
    monkeypatch.setenv("DEV_JWT_SECRET", "dev-secret")
    monkeypatch.setenv("DEV_JWT_ISSUER", "https://dev-issuer.local")
    monkeypatch.setenv("DEV_JWT_AUDIENCE", "zero-trust-api")

    def fake_query_opa(input_document: dict[str, Any]) -> dict[str, Any]:
        subject = input_document.get("subject", {})
        resource = input_document.get("resource", {})
        request_data = input_document.get("request", {})
        roles = subject.get("roles", [])

        is_get = request_data.get("method") == "GET"
        tenant_match = subject.get("tenant") == resource.get("tenant")
        has_read_role = any(role in roles for role in ["reader", "writer", "admin"])

        if is_get and tenant_match and has_read_role:
            return {"allow": True, "reason": "allow_rbac_abac_read"}

        return {"allow": False, "reason": "deny_by_default"}

    def fake_fetch_resources_for_tenant(tenant_id: str, limit: int = 100) -> list[dict[str, Any]]:
        del limit
        return [{"id": 1, "tenant_id": tenant_id, "name": "alpha-doc"}]

    monkeypatch.setattr("src.api.main.query_opa", fake_query_opa)
    monkeypatch.setattr("src.api.main.fetch_resources_for_tenant", fake_fetch_resources_for_tenant)

    with TestClient(app) as test_client:
        yield test_client


def test_missing_token_returns_401(client: TestClient) -> None:
    response = client.get("/v1/tenant/tenant-a/resource")

    assert response.status_code == 401


def test_valid_token_wrong_tenant_returns_403(client: TestClient) -> None:
    token = make_dev_hs256_token(secret="dev-secret", tenant="tenant-a", roles=["reader"])

    response = client.get(
        "/v1/tenant/tenant-b/resource",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 403
    assert response.json()["detail"]["reason"] == "deny_by_default"


def test_valid_token_correct_role_and_tenant_returns_200(client: TestClient) -> None:
    token = make_dev_hs256_token(secret="dev-secret", tenant="tenant-a", roles=["reader"])

    response = client.get(
        "/v1/tenant/tenant-a/resource",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    body = response.json()
    assert isinstance(body, list)
    assert body[0]["tenant_id"] == "tenant-a"
