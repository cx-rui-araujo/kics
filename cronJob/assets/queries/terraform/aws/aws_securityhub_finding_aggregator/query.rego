package main

__rego_metadata__ := {
  "id": "AWS_SHF001",
  "title": "Disallowed NO_REGIONS linking_mode in aws_securityhub_finding_aggregator",
  "severity": "MEDIUM",
  "type": "VULNERABILITY",
  "data_source": "terraform plan"
}

violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_securityhub_finding_aggregator"
  resource.change.after.linking_mode == "NO_REGIONS"
}