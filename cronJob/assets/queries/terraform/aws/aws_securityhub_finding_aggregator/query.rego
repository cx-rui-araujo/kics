package main

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_securityhub_finding_aggregator"
  resource.change.after.linking_mode == "NO_REGIONS"
  msg := sprintf("Resource '%s' disables cross-region aggregation by setting linking_mode to NO_REGIONS", [resource.address])
}