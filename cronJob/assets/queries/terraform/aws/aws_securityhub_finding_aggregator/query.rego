package kics

__rego_metadata__ := {
  "id": "KICS-AWS-SECURITYHUB-AGG-1",
  "title": "Security Hub Finding Aggregator with NO_REGIONS linking mode",
  "severity": "HIGH",
  "description": "Security Hub aggregator linking_mode set to NO_REGIONS can result in missing findings across regions.",
  "reference_id": "AWS008",
  "query": "aws_securityhub_finding_aggregator_no_regions"
}

violation[resource] {
  resource := input.resources[_]
  resource.Type == "aws_securityhub_finding_aggregator"
  resource.Config.linking_mode == "NO_REGIONS"
}