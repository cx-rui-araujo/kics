package terraform.securityhub

__rego_metadata__ := {
  "id": "KICS-0001",
  "title": "AWS Security Hub finding aggregator NO_REGIONS linking_mode",
  "description": "Ensure that aws_securityhub_finding_aggregator does not use NO_REGIONS for linking_mode, as it may miss findings from regions.",
  "severity": "MEDIUM",
  "type": "Issue",
  "platform": "Terraform"
}

violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_securityhub_finding_aggregator"
  resource.change.after.linking_mode == "NO_REGIONS"
}