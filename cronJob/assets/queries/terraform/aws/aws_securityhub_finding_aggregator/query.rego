package terraform.securityhub

violation[{"resource": resource.address, "message": msg}] {
  resource := data.resources.aws_securityhub_finding_aggregator[_]
  resource.values.linking_mode == "NO_REGIONS"
  msg := sprintf("SecurityHub Finding Aggregator '%s' configured with NO_REGIONS, missing inter-region aggregation.", [resource.address])
}