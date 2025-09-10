package terraform.securityhub

__rego_metadata__ := {
    "id": "AWSSEC_001",
    "title": "Avoid disabling regional aggregation for Security Hub finding aggregator",
    "severity": "MEDIUM",
    "description": "Using linking_mode = \"NO_REGIONS\" can cause missing findings in all but the home region, leading to gaps in coverage.",
    "documentation": {
        "recommendation": "Use linking_mode = \"ALL_REGIONS\" to ensure findings are aggregated from all regions.",
        "links": ["https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/securityhub_finding_aggregator#linking_mode"]
    }
}

violation[resource] {
    resource := input.resource_blocks[_]
    resource.type == "aws_securityhub_finding_aggregator"
    attr := resource.GetAttribute("linking_mode")
    attr != nil
    attr.Value == "NO_REGIONS"
}