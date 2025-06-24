package kics

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_securityhub_finding_aggregator"
  linking := resource.change.after.linking_mode
  linking == "NO_REGIONS"
  msg := sprintf("Resource '%s' uses linking_mode NO_REGIONS, which prevents cross-region aggregation and may miss security findings.", [resource.address])
}