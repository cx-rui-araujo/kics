package terraform.securityhub.aggregator

__rego_metadata__ := {
  "id": "TERRAFORM_AWS_9001",
  "title": "Security Hub Finding Aggregator uses NO_REGIONS linking_mode",
  "severity": "MEDIUM",
  "type": "MISCONFIGURATION",
  "description": "Using linking_mode = NO_REGIONS may leave security findings in specific regions unaggregated and unmonitored."
}

denied_aggregators[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_securityhub_finding_aggregator"
  resource.change.after.linking_mode == "NO_REGIONS"
}

violation[resource] {
  denied_aggregators[resource]
}