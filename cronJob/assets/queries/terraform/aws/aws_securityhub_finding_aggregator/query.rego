package kics

violation[resource] {
  __rule__.id = "AWSSECURITYHUB_FAGG_NO_REGIONS"
  __rule__.description = "SecurityHub Finding Aggregator with linking_mode set to NO_REGIONS may skip region data aggregation"
  __rule__.severity = "HIGH"
  resource := input.plan.resource_changes[_]
  resource.type == "aws_securityhub_finding_aggregator"
  resource.change.after.linking_mode == "NO_REGIONS"
}