package terraform.securityhub

violation[resource] {
  resource := input.resource
  resource.type == "aws_securityhub_finding_aggregator"
  resource.change.after.linking_mode == "NO_REGIONS"
}