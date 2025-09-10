package terraform.aws_rum

__rego_metadata__ = {
    "id": "KICS-AWS-RUM-001",
    "title": "AWS RUM App Monitor should specify domain",
    "severity": "HIGH",
    "type": "MISCONFIGURATION"
}

violation[{
    "msg": msg,
    "resource": resource.address
}] {
    input.resource_changes[_] as resource
    resource.type == "aws_rum_app_monitor"
    resource.change.after != null
    not resource.change.after.domain
    msg := sprintf("Resource '%s' does not specify 'domain', leading to potential RUM misconfiguration.", [resource.address])
}