package main

violation[{"message": msg}] {
  resource := input.resource_changes[_]
  resource.type == "aws_securityhub_finding_aggregator"
  resource.change.after.linking_mode == "NO_REGIONS"
  msg := "SecurityHub finding aggregator 'linking_mode' is set to NO_REGIONS, disabling cross-region findings aggregation and potentially missing critical findings across regions."
}