package kics

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_securityhub_finding_aggregator"
  config := resource.change.after
  config.linking_mode == "NO_REGIONS"
  msg = sprintf("Security Hub finding aggregator 'linking_mode' is set to NO_REGIONS, which may omit regional findings and lead to gaps in security coverage", [])
}