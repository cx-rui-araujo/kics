package terraform.securityhub

default allow = false

violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_securityhub_finding_aggregator"
  after := resource.change.after
  after.linking_mode == "NO_REGIONS"
}