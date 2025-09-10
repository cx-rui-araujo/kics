package main

violation[resource] {
  resource := input.resource_values[_]
  resource.kind == "aws_securityhub_finding_aggregator"
  resource.values.linking_mode == "NO_REGIONS"
}
