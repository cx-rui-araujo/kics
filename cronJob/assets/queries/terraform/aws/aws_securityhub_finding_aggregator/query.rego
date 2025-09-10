package terraform.kics.aws

__rego_metadata__ := {
  "id": "KICS-0001",
  "title": "Ensure Security Hub Aggregator does not use NO_REGIONS linking_mode",
  "description": "Using NO_REGIONS linking_mode can cause missing findings across regions.",
  "rationale": "Aggregating findings across all regions ensures consistent visibility of security alerts.",
  "severity": "MEDIUM",
  "provider": "aws",
  "resource_type": "aws_securityhub_finding_aggregator"
}

violation[resource] {
  resource := tfconfig.resource.aws_securityhub_finding_aggregator[name]
  resource.values.linking_mode == "NO_REGIONS"
}