package terraform.aws_securityhub

__rego_metadata__ := {
  "id": "AWS_SH_UNMONITORED_REGIONS",
  "title": "Security Hub finding aggregator should not use NO_REGIONS linking_mode",
  "severity": "MEDIUM",
  "category": "Best Practices",
  "description": "Using linking_mode = NO_REGIONS in aws_securityhub_finding_aggregator excludes region coverage and may miss findings."
}

deny[msg] {
  resource := input.resources[_]
  resource.type == "aws_securityhub_finding_aggregator"
  resource.values.linking_mode == "NO_REGIONS"
  msg := sprintf("Resource '%s' uses linking_mode 'NO_REGIONS', which disables region aggregation", [resource.address])
}