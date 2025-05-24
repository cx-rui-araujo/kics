package kics

violation[{"msg": msg}] {
  input.resource.type == "aws_securityhub_finding_aggregator"
  input.resource.values.linking_mode == "NO_REGIONS"
  msg := sprintf("Security Hub finding aggregator '%s' uses NO_REGIONS linking_mode, potentially missing regional findings", [input.resource.name])
}