package terraform.aws.SecurityHubFindingAggregator

violation[issue] {
  input.kind == "terraform"
  resource := input.resource_changes[_]
  resource.type == "aws_securityhub_finding_aggregator"
  mode := resource.change.after.linking_mode
  mode == "NO_REGIONS"
  issue := {
    "message": "Security Hub finding aggregator uses NO_REGIONS linking_mode, which may prevent aggregation of findings across regions.",
    "resource": resource.address,
    "rule_id": "KICS-9999",
    "severity": "HIGH"
  }
}