package main
import data.tfplan

__rego_meta__ := {
    "id": "KICS-TERRAFORM-SECURITYHUB-1",
    "title": "Avoid NO_REGIONS linking_mode in aws_securityhub_finding_aggregator",
    "severity": "LOW",
    "type": "MISCONFIGURATION"
}

violation[{"msg": msg, "resource": resource.address}] {
    resource := data.tfplan.resource_changes[_]
    resource.type == "aws_securityhub_finding_aggregator"
    after := resource.change.after
    after.linking_mode == "NO_REGIONS"
    msg := sprintf("Resource '%s' has linking_mode set to NO_REGIONS which may cause missing cross-region findings", [resource.address])
}
