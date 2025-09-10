package main

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_securityhub_finding_aggregator"
  resource.change.after.linking_mode == "NO_REGIONS"
  msg := "SecurityHub finding aggregator configured with NO_REGIONS linking_mode, disabling cross-region aggregation."
}