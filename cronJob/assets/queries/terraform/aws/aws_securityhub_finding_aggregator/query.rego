package main

__rego_metadata__ = {
  "id": "AWS_SecurityHub_Finding_Aggregator_NO_REGIONS",
  "title": "Avoid NO_REGIONS linking_mode in aws_securityhub_finding_aggregator",
  "severity": "MEDIUM",
  "type": "VIOLATION"
}

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_securityhub_finding_aggregator"
  mode := resource.change.after.linking_mode
  mode == "NO_REGIONS"
  msg := sprintf("Found linking_mode set to NO_REGIONS for resource %v", [resource.address])
}
