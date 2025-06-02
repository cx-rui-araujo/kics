package main

__rego_metadata__ = {
    "id": "AWSSECURITYHUB_NO_REGIONS",
    "title": "Avoid using NO_REGIONS for Security Hub finding aggregator",
    "severity": "MEDIUM",
    "type": "ISSUE",
    "description": "Setting linking_mode to NO_REGIONS disables aggregation across regions and may hide security findings."
}

violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_securityhub_finding_aggregator"
  resource.change.after.linking_mode == "NO_REGIONS"
}