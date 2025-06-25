package main

__rego_metadoc__ := {
  "id": "KICS_AWS_SECURITYHUB_FINDING_AGGREGATOR_NO_REGIONS",
  "version": "1.0.0",
  "platform": "Terraform",
  "categories": ["misconfiguration"],
  "severity": "LOW",
  "description": "aws_securityhub_finding_aggregator with linking_mode NO_REGIONS may miss region-specific findings"
}

deny[resource] {
  resource := input.resource.aws_securityhub_finding_aggregator[_]
  resource.values.linking_mode == "NO_REGIONS"
}