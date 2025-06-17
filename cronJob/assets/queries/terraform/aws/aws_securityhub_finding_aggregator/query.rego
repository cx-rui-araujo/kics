package kics

__rego_metadata__ = {"id": "KICS-AWS-SECURITYHUB-FINDING-AGG-001", "title": "SecurityHub Finding Aggregator should not use NO_REGIONS linking_mode", "severity": "HIGH", "resource_type": "aws_securityhub_finding_aggregator", "description": "Detects aws_securityhub_finding_aggregator resources with linking_mode set to NO_REGIONS which disables regional aggregation."}

denied[message] {
  resource := input.resource_changes[_]
  resource.type == "aws_securityhub_finding_aggregator"
  linking_mode := resource.change.after.linking_mode
  linking_mode == "NO_REGIONS"
  message := sprintf("Resource '%s' uses linking_mode NO_REGIONS which may skip findings from all regions.", [resource.address])
}