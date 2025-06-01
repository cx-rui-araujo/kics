package main

__kics_metadata__ = {"id": "AWS_SECURITYHUB_FINDING_AGGREGATOR_NO_REGIONS", "title": "Avoid using NO_REGIONS for aws_securityhub_finding_aggregator", "severity": "MEDIUM", "type": "Misconfiguration"}

deny[msg] {
  resource := input.resource
  resource.type == "aws_securityhub_finding_aggregator"
  resource.values.linking_mode == "NO_REGIONS"
  msg := sprintf("Resource %v uses NO_REGIONS linking_mode which may disable regional aggregation", [resource.address])
}