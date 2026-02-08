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

allow if {
    tenant_match
    input.request.method == "GET"
    has_role("reader")
}

allow if {
    tenant_match
    input.request.method == "GET"
    has_role("writer")
}

allow if {
    tenant_match
    input.request.method == "GET"
    has_role("admin")
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

reason := "allow_rbac_read" if {
    tenant_match
    input.request.method == "GET"
    has_role("reader")
}

reason := "allow_rbac_read" if {
    tenant_match
    input.request.method == "GET"
    has_role("writer")
}

reason := "allow_rbac_read" if {
    tenant_match
    input.request.method == "GET"
    has_role("admin")
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
