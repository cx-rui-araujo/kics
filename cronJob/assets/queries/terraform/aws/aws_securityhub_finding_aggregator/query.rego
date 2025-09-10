package main

__rego_metadata__ := {
  "id": "AWS_SH_FINDING_AGGREGATOR_001",
  "title": "Avoid NO_REGIONS linking_mode for Security Hub finding aggregator",
  "description": "Using NO_REGIONS linking_mode disables cross-region finding aggregation, which may lead to missing critical security findings.",
  "severity": "MEDIUM",
  "category": "Misconfiguration",
  "platform": "Terraform"
}

violation[msg] {
  resource := input.resource_changes.aws_securityhub_finding_aggregator[_]
  resource.change.after.linking_mode == "NO_REGIONS"
  msg := sprintf("Resource '%v' uses NO_REGIONS linking_mode, disabling cross-region finding aggregation", [resource.address])
}