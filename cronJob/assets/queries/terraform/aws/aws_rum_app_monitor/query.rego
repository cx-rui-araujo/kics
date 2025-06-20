package main

__rego_metadata__ := {
    "id": "KICS_AWS_RUM_1",
    "title": "Ensure aws_rum_app_monitor domain_list does not allow wildcard or empty domains",
    "severity": "MEDIUM",
    "type": "VULNERABILITY",
    "metadata": {
        "source": "terraform",
        "reference_id": "AWS.RUM.AppMonitor.DomainList"
    }
}

violation[resource] {
    resource := input.resource_changes[_]
    resource.type == "aws_rum_app_monitor"
    after := resource.change.after
    domains := after.domain_list
    count(domains) > 0
    some i
    domain := domains[i]
    domain == "*"
}

violation[resource] {
    resource := input.resource_changes[_]
    resource.type == "aws_rum_app_monitor"
    after := resource.change.after
    domains := after.domain_list
    count(domains) > 0
    some i
    domain := domains[i]
    startswith(domain, "http")
}