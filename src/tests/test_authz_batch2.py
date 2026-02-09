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
    claims: dict[str, Any] | None = None,
) -> str:
    payload = {
        "sub": "user-1",
        "tenant": "tenant-a",
        "roles": ["reader"],
        "attrs": {},
        "iss": "https://dev-issuer.local",
        "aud": "zero-trust-api",
        "exp": int(time.time()) + 3600,
    }
    if claims:
        payload.update(claims)

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


def _auth_header(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_bac_011_post_method_mismatch_returns_405(client: TestClient) -> None:
    token = make_dev_hs256_token(secret="dev-secret")

    response = client.post("/v1/tenant/tenant-a/resource", headers=_auth_header(token))

    assert response.status_code == 405


def test_bac_012_delete_method_mismatch_returns_405(client: TestClient) -> None:
    token = make_dev_hs256_token(secret="dev-secret")

    response = client.delete("/v1/tenant/tenant-a/resource", headers=_auth_header(token))

    assert response.status_code == 405


def test_bac_013_path_case_mismatch_returns_404(client: TestClient) -> None:
    token = make_dev_hs256_token(secret="dev-secret")

    response = client.get("/v1/TENANT/tenant-a/resource", headers=_auth_header(token))

    assert response.status_code == 404


def test_bac_014_encoded_slash_in_tenant_path_returns_404(client: TestClient) -> None:
    token = make_dev_hs256_token(secret="dev-secret")

    response = client.get("/v1/tenant/tenant-a%2Ftenant-b/resource", headers=_auth_header(token))

    assert response.status_code == 404


def test_bac_015_extra_path_segment_returns_404(client: TestClient) -> None:
    token = make_dev_hs256_token(secret="dev-secret")

    response = client.get("/v1/tenant/tenant-a/resource/extra", headers=_auth_header(token))

    assert response.status_code == 404


def test_bac_016_encoded_dotdot_tenant_denied_403(client: TestClient) -> None:
    token = make_dev_hs256_token(secret="dev-secret", claims={"tenant": "tenant-a", "roles": ["reader"]})

    response = client.get("/v1/tenant/%2E%2E/resource", headers=_auth_header(token))

    assert response.status_code == 403
    assert response.json()["detail"]["reason"] == "deny_by_default"


def test_bac_017_attrs_claim_wrong_type_denied_401(client: TestClient) -> None:
    token = make_dev_hs256_token(secret="dev-secret", claims={"attrs": ["env", "prod"]})

    response = client.get("/v1/tenant/tenant-a/resource", headers=_auth_header(token))

    assert response.status_code == 401
    assert response.json()["detail"] == "token_attrs_invalid"


def test_bac_018_missing_env_attribute_denied_403(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    def env_required_query_opa(input_document: dict[str, Any]) -> dict[str, Any]:
        subject = input_document.get("subject", {})
        resource = input_document.get("resource", {})
        subject_attrs = subject.get("attrs", {})

        if subject.get("tenant") == resource.get("tenant") and subject_attrs.get("env") == "prod":
            return {"allow": True, "reason": "allow_rbac_abac_read"}

        return {"allow": False, "reason": "deny_by_default"}

    monkeypatch.setattr("src.api.main.query_opa", env_required_query_opa)

    token = make_dev_hs256_token(secret="dev-secret", claims={"attrs": {}})
    response = client.get("/v1/tenant/tenant-a/resource", headers=_auth_header(token))

    assert response.status_code == 403
    assert response.json()["detail"]["reason"] == "deny_by_default"


def test_bac_019_env_attribute_mismatch_denied_403(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    def env_required_query_opa(input_document: dict[str, Any]) -> dict[str, Any]:
        subject = input_document.get("subject", {})
        resource = input_document.get("resource", {})
        subject_attrs = subject.get("attrs", {})

        if subject.get("tenant") == resource.get("tenant") and subject_attrs.get("env") == "prod":
            return {"allow": True, "reason": "allow_rbac_abac_read"}

        return {"allow": False, "reason": "deny_by_default"}

    monkeypatch.setattr("src.api.main.query_opa", env_required_query_opa)

    token = make_dev_hs256_token(secret="dev-secret", claims={"attrs": {"env": "dev"}})
    response = client.get("/v1/tenant/tenant-a/resource", headers=_auth_header(token))

    assert response.status_code == 403
    assert response.json()["detail"]["reason"] == "deny_by_default"


def test_bac_020_clearance_attribute_insufficient_denied_403(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def restricted_clearance_query_opa(input_document: dict[str, Any]) -> dict[str, Any]:
        subject = input_document.get("subject", {})
        resource = input_document.get("resource", {})
        clearance = subject.get("attrs", {}).get("clearance")

        if subject.get("tenant") == resource.get("tenant") and clearance == "restricted":
            return {"allow": True, "reason": "allow_rbac_abac_read"}

        return {"allow": False, "reason": "deny_by_default"}

    monkeypatch.setattr("src.api.main.query_opa", restricted_clearance_query_opa)

    token = make_dev_hs256_token(secret="dev-secret", claims={"attrs": {"clearance": "internal"}})
    response = client.get("/v1/tenant/tenant-a/resource", headers=_auth_header(token))

    assert response.status_code == 403
    assert response.json()["detail"]["reason"] == "deny_by_default"
