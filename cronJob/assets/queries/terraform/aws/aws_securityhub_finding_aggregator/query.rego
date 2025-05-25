package terraform.aws_securityhub_finding_aggregator

violation[{"msg": msg, "resource": resource.address}] {
  resource := input.resource_changes[_]
  resource.type == "aws_securityhub_finding_aggregator"
  after := resource.change.after
  after.linking_mode == "NO_REGIONS"
  msg := sprintf("Resource '%s' has linking_mode set to NO_REGIONS, disabling cross-region aggregation", [resource.address])
}