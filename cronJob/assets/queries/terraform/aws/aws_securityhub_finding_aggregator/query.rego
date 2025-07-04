package kics

deny[issue] {
  resource := input.resource_changes[_]
  resource.type == "aws_securityhub_finding_aggregator"
  mode := resource.change.after.linking_mode
  mode == "NO_REGIONS"

  issue := {
    "message": "Setting linking_mode to NO_REGIONS disables cross-region findings aggregation, reducing security visibility.",
    "resource": resource.address
  }
}