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


def make_dev_token(
    *,
    secret: str,
    claims: dict[str, Any] | None = None,
    header_overrides: dict[str, Any] | None = None,
    signing_secret: str | None = None,
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
    if header_overrides:
        header.update(header_overrides)

    header_segment = _b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_segment = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{header_segment}.{payload_segment}".encode("ascii")
    secret_to_use = signing_secret if signing_secret is not None else secret
    signature = hmac.new(secret_to_use.encode("utf-8"), signing_input, hashlib.sha256).digest()
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


def _auth_header(token: str, scheme: str = "Bearer") -> dict[str, str]:
    return {"Authorization": f"{scheme} {token}"}


def test_bac_021_invalid_signature_denied_401(client: TestClient) -> None:
    token = make_dev_token(secret="dev-secret", signing_secret="wrong-secret")

    response = client.get("/v1/tenant/tenant-a/resource", headers=_auth_header(token))

    assert response.status_code == 401
    assert response.json()["detail"] == "token_signature_invalid"


def test_bac_022_missing_subject_denied_401(client: TestClient) -> None:
    token = make_dev_token(secret="dev-secret", claims={"sub": ""})

    response = client.get("/v1/tenant/tenant-a/resource", headers=_auth_header(token))

    assert response.status_code == 401
    assert response.json()["detail"] == "token_subject_invalid"


def test_bac_023_missing_exp_denied_401(client: TestClient) -> None:
    token = make_dev_token(secret="dev-secret", claims={"exp": None})

    response = client.get("/v1/tenant/tenant-a/resource", headers=_auth_header(token))

    assert response.status_code == 401
    assert response.json()["detail"] == "token_missing_exp"


def test_bac_024_audience_list_mismatch_denied_401(client: TestClient) -> None:
    token = make_dev_token(secret="dev-secret", claims={"aud": ["x", "y"]})

    response = client.get("/v1/tenant/tenant-a/resource", headers=_auth_header(token))

    assert response.status_code == 401
    assert response.json()["detail"] == "token_audience_mismatch"


def test_bac_025_wrong_algorithm_denied_401(client: TestClient) -> None:
    token = make_dev_token(secret="dev-secret", header_overrides={"alg": "HS512"})

    response = client.get("/v1/tenant/tenant-a/resource", headers=_auth_header(token))

    assert response.status_code == 401
    assert response.json()["detail"] == "token_algorithm_invalid"


def test_bac_026_roles_with_non_string_member_denied_401(client: TestClient) -> None:
    token = make_dev_token(secret="dev-secret", claims={"roles": ["reader", 42]})

    response = client.get("/v1/tenant/tenant-a/resource", headers=_auth_header(token))

    assert response.status_code == 401
    assert response.json()["detail"] == "token_roles_invalid"


def test_bac_027_roles_with_empty_member_denied_401(client: TestClient) -> None:
    token = make_dev_token(secret="dev-secret", claims={"roles": [""]})

    response = client.get("/v1/tenant/tenant-a/resource", headers=_auth_header(token))

    assert response.status_code == 401
    assert response.json()["detail"] == "token_roles_invalid"


def test_bac_028_missing_dev_secret_denied_401(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    token = make_dev_token(secret="dev-secret")
    monkeypatch.delenv("DEV_JWT_SECRET", raising=False)

    response = client.get("/v1/tenant/tenant-a/resource", headers=_auth_header(token))

    assert response.status_code == 401
    assert response.json()["detail"] == "dev_jwt_secret_missing"


def test_bac_029_opa_timeout_fail_closed_denied_403(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    token = make_dev_token(secret="dev-secret")

    monkeypatch.setattr(
        "src.api.main.query_opa",
        lambda _input: {"allow": False, "reason": "deny_opa_timeout"},
    )

    response = client.get("/v1/tenant/tenant-a/resource", headers=_auth_header(token))

    assert response.status_code == 403
    assert response.json()["detail"]["reason"] == "deny_opa_timeout"


def test_bac_030_database_unavailable_returns_503(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    token = make_dev_token(secret="dev-secret")

    monkeypatch.setattr("src.api.main.query_opa", lambda _input: {"allow": True, "reason": "allow_rbac_abac_read"})

    def fail_fetch(_tenant_id: str, limit: int = 100) -> list[dict[str, Any]]:
        del limit
        raise RuntimeError("db down")

    monkeypatch.setattr("src.api.main.fetch_resources_for_tenant", fail_fetch)

    response = client.get("/v1/tenant/tenant-a/resource", headers=_auth_header(token))

    assert response.status_code == 503
    assert response.json()["detail"]["reason"] == "database_unavailable"


def test_bac_031_missing_roles_claim_defaults_to_deny_403(client: TestClient) -> None:
    token = make_dev_token(secret="dev-secret", claims={"roles": None})

    response = client.get("/v1/tenant/tenant-a/resource", headers=_auth_header(token))

    assert response.status_code == 403
    assert response.json()["detail"]["reason"] == "deny_by_default"


def test_bac_032_lowercase_bearer_scheme_is_accepted_200(client: TestClient) -> None:
    token = make_dev_token(secret="dev-secret")

    response = client.get("/v1/tenant/tenant-a/resource", headers=_auth_header(token, scheme="bearer"))

    assert response.status_code == 200
