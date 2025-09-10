package main

deny[{"resource": resource.address, "message": "Security Hub finding aggregator uses NO_REGIONS linking_mode, disabling regional aggregation"}] {
  resource := input.resource_changes[_]
  resource.type == "aws_securityhub_finding_aggregator"
  resource.change.after.linking_mode == "NO_REGIONS"
}