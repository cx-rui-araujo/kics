package terraform.securityhub

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_securityhub_finding_aggregator"
  resource.change.after.linking_mode == "NO_REGIONS"
  msg := sprintf("Security Hub Finding Aggregator '%s' uses linking_mode NO_REGIONS, disabling cross-region aggregation", [resource.address])
}