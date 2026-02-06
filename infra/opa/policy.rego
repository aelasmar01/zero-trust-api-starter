package authz

default allow := false
default reason := "deny_by_default"

allow if {
    input.request.method == "GET"
    input.subject.tenant != ""
    input.subject.tenant == input.resource.tenant
}

reason := "allow_tenant_read" if allow

decision := {
    "allow": allow,
    "reason": reason,
}
