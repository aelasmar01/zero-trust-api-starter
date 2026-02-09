# Misuse Catalog v1

This catalog maps authorization misuse scenarios to the automated test suite and OWASP API Security categories.

## Scope
- Primary endpoint under test: `GET /v1/tenant/{tenant_id}/resource`
- Scenario source files:
  - `src/tests/test_authz_negative_batch1.py`
  - `src/tests/test_authz_batch2.py`
  - `src/tests/test_authz_batch3.py`

## OWASP mapping keys
- `API1:2023` Broken Object Level Authorization
- `API2:2023` Broken Authentication
- `API3:2023` Broken Object Property Level Authorization
- `API4:2023` Unrestricted Resource Consumption
- `API5:2023` Broken Function Level Authorization
- `API8:2023` Security Misconfiguration

## Scenario Catalog
| Scenario ID | Test case | Misuse pattern | Expected result | Expected deny reason/status | OWASP mapping |
|---|---|---|---|---|---|
| BAC-001 | `test_bac_001_missing_token_denied_401` | Request without bearer token | Deny | `401 authorization_header_missing` | API2:2023 |
| BAC-002 | `test_bac_002_non_bearer_authorization_header_denied_401` | Wrong auth scheme (`Basic`) | Deny | `401 authorization_header_invalid` | API2:2023 |
| BAC-003 | `test_bac_003_malformed_jwt_format_denied_401` | Malformed JWT structure | Deny | `401 token_decode_failed` / format invalid | API2:2023 |
| BAC-004 | `test_bac_004_expired_token_denied_401` | Expired token replay | Deny | `401 token_expired` | API2:2023 |
| BAC-005 | `test_bac_005_wrong_issuer_denied_401` | Token from untrusted issuer | Deny | `401 token_issuer_invalid` | API2:2023 |
| BAC-006 | `test_bac_006_wrong_audience_denied_401` | Token not intended for this API | Deny | `401 token_audience_mismatch` | API2:2023 |
| BAC-007 | `test_bac_007_empty_tenant_claim_denied_401` | Empty tenant claim bypass attempt | Deny | `401 token_tenant_invalid` | API1:2023 |
| BAC-008 | `test_bac_008_roles_claim_wrong_type_denied_401` | Invalid roles claim type | Deny | `401 token_roles_invalid` | API2:2023 |
| BAC-009 | `test_bac_009_tenant_mismatch_denied_403` | Cross-tenant object access | Deny | `403 deny_by_default` | API1:2023 |
| BAC-010 | `test_bac_010_missing_read_role_denied_403` | Role removed, still attempts read | Deny | `403 deny_by_default` | API5:2023 |
| BAC-011 | `test_bac_011_post_method_mismatch_returns_405` | Unsupported method probing | Deny | `405` | API8:2023 |
| BAC-012 | `test_bac_012_delete_method_mismatch_returns_405` | Unsupported delete probing | Deny | `405` | API5:2023 |
| BAC-013 | `test_bac_013_path_case_mismatch_returns_404` | Route casing fuzzing | Deny | `404` | API8:2023 |
| BAC-014 | `test_bac_014_encoded_slash_in_tenant_path_returns_404` | Path confusion with encoded slash | Deny | `404` | API8:2023 |
| BAC-015 | `test_bac_015_extra_path_segment_returns_404` | Route traversal via extra segment | Deny | `404` | API8:2023 |
| BAC-016 | `test_bac_016_encoded_dotdot_tenant_denied_403` | Encoded `..` tenant breakout attempt | Deny | `403 deny_by_default` | API1:2023 |
| BAC-017 | `test_bac_017_attrs_claim_wrong_type_denied_401` | Invalid attrs claim structure | Deny | `401 token_attrs_invalid` | API2:2023 |
| BAC-018 | `test_bac_018_missing_env_attribute_denied_403` | Missing ABAC env attribute | Deny | `403 deny_by_default` | API3:2023 |
| BAC-019 | `test_bac_019_env_attribute_mismatch_denied_403` | ABAC env mismatch | Deny | `403 deny_by_default` | API3:2023 |
| BAC-020 | `test_bac_020_clearance_attribute_insufficient_denied_403` | ABAC clearance too low | Deny | `403 deny_by_default` | API3:2023 |
| BAC-021 | `test_bac_021_invalid_signature_denied_401` | Token tampering / forged signature | Deny | `401 token_signature_invalid` | API2:2023 |
| BAC-022 | `test_bac_022_missing_subject_denied_401` | Missing/empty subject identity | Deny | `401 token_subject_invalid` | API2:2023 |
| BAC-023 | `test_bac_023_missing_exp_denied_401` | Token without expiration | Deny | `401 token_missing_exp` | API2:2023 |
| BAC-024 | `test_bac_024_audience_list_mismatch_denied_401` | Audience list excludes API | Deny | `401 token_audience_mismatch` | API2:2023 |
| BAC-025 | `test_bac_025_wrong_algorithm_denied_401` | JWT alg confusion attempt | Deny | `401 token_algorithm_invalid` | API2:2023 |
| BAC-026 | `test_bac_026_roles_with_non_string_member_denied_401` | Roles contains invalid member type | Deny | `401 token_roles_invalid` | API2:2023 |
| BAC-027 | `test_bac_027_roles_with_empty_member_denied_401` | Empty role entry abuse | Deny | `401 token_roles_invalid` | API2:2023 |
| BAC-028 | `test_bac_028_missing_dev_secret_denied_401` | Misconfigured auth secret | Deny | `401 dev_jwt_secret_missing` | API8:2023 |
| BAC-029 | `test_bac_029_opa_timeout_fail_closed_denied_403` | PDP timeout fail-open attempt | Deny | `403 deny_opa_timeout` | API8:2023 |
| BAC-030 | `test_bac_030_database_unavailable_returns_503` | DB dependency outage during authorized request | Fail safely | `503 database_unavailable` | API4:2023 |
| BAC-031 | `test_bac_031_missing_roles_claim_defaults_to_deny_403` | Missing roles defaults to deny | Deny | `403 deny_by_default` | API5:2023 |
| BAC-032 | `test_bac_032_lowercase_bearer_scheme_is_accepted_200` | Header scheme casing variation | Allow (expected) | `200` | API2:2023 |

## Notes
- This suite intentionally prioritizes Broken Access Control paths (tenant breakout, role bypass, ABAC bypass, and fail-open conditions).
- Scenario IDs are stable and should be referenced in future policy/test changes.
