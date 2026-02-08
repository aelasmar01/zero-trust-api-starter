package authz

default allow := false
default reason := "deny_by_default"

tenant_match if {
    input.subject.tenant != ""
    input.subject.tenant == input.resource.tenant
}

has_role(role) if {
    is_array(input.subject.roles)
    role in input.subject.roles
}

subject_env := object.get(object.get(input.subject, "attrs", {}), "env", "")
resource_env := object.get(object.get(input.resource, "attrs", {}), "env", "")
resource_classification := object.get(object.get(input.resource, "attrs", {}), "data_classification", "internal")
subject_clearance := object.get(object.get(input.subject, "attrs", {}), "clearance", "internal")

env_compatible if {
    resource_env == ""
}

env_compatible if {
    resource_env != ""
    subject_env != ""
    subject_env == resource_env
}

classification_compatible if {
    resource_classification == "internal"
}

classification_compatible if {
    resource_classification == "restricted"
    subject_clearance == "restricted"
}

abac_allows_read if {
    env_compatible
    classification_compatible
}

allow if {
    tenant_match
    input.request.method == "GET"
    has_role("reader")
    abac_allows_read
}

allow if {
    tenant_match
    input.request.method == "GET"
    has_role("writer")
    abac_allows_read
}

allow if {
    tenant_match
    input.request.method == "GET"
    has_role("admin")
    abac_allows_read
}

allow if {
    tenant_match
    input.request.method == "POST"
    has_role("writer")
}

allow if {
    tenant_match
    input.request.method == "POST"
    has_role("admin")
}

allow if {
    tenant_match
    input.request.method == "DELETE"
    has_role("admin")
}

reason := "allow_rbac_abac_read" if {
    tenant_match
    input.request.method == "GET"
    has_role("reader")
    abac_allows_read
}

reason := "allow_rbac_abac_read" if {
    tenant_match
    input.request.method == "GET"
    has_role("writer")
    abac_allows_read
}

reason := "allow_rbac_abac_read" if {
    tenant_match
    input.request.method == "GET"
    has_role("admin")
    abac_allows_read
}

reason := "allow_rbac_write" if {
    tenant_match
    input.request.method == "POST"
    has_role("writer")
}

reason := "allow_rbac_write" if {
    tenant_match
    input.request.method == "POST"
    has_role("admin")
}

reason := "allow_rbac_delete" if {
    tenant_match
    input.request.method == "DELETE"
    has_role("admin")
}

decision := {
    "allow": allow,
    "reason": reason,
}
