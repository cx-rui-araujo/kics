package main

__rego_metadata__ := {
  "id": "TC_AWS_SECURITYHUB_FINDING_AGGREGATOR_LINKING_MODE",
  "title": "Security Hub Finding Aggregator using NO_REGIONS",
  "severity": "MEDIUM",
  "type": "terraform",
  "subtype": "resource",
}

violation[violation] {
  change := input.resource_changes[_]
  change.change.after.type == "aws_securityhub_finding_aggregator"
  change.change.after.values.linking_mode == "NO_REGIONS"
  violation := {
    "msg": "Security Hub Finding Aggregator with linking_mode NO_REGIONS may miss cross-region security findings",
    "resource": change.address
  }
}