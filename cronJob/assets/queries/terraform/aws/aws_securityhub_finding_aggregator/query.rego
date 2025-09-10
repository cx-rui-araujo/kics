package terraform.securityhub

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_securityhub_finding_aggregator"
  resource.change.after.linking_mode == "NO_REGIONS"
  msg := "Setting linking_mode to NO_REGIONS disables cross-region aggregation and may lead to incomplete security coverage"
}