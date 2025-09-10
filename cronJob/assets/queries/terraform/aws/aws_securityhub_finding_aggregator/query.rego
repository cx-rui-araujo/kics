package main

__rego_metadata__ := {
  "id": "AWS_SECURITYHUB_FINDING_AGGREGATOR_1",
  "title": "Avoid NO_REGIONS for aws_securityhub_finding_aggregator linking_mode",
  "severity": "HIGH",
  "type": "VIOLATION",
}

violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_securityhub_finding_aggregator"
  resource.change.after.linking_mode == "NO_REGIONS"
}