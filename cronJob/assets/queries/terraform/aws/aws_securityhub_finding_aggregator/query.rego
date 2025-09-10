package main

deny[issue] {
  resource := input.resource_changes[_]
  resource.type == "aws_securityhub_finding_aggregator"
  after := resource.change.after
  after.linking_mode == "NO_REGIONS"
  issue := "aws_securityhub_finding_aggregator linking_mode is set to NO_REGIONS which may exclude regions from aggregation"
}