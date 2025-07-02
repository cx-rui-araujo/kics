package kics

__rego_metadata__ = {
  "id": "KICS_AWS_045", 
  "title": "Avoid NO_REGIONS linking_mode on Security Hub Finding Aggregator", 
  "severity": "MEDIUM", 
  "type": "VIOLATION"
}

deny[res] {
  res := input.terraform.modules[_].resources[_]
  res.type == "aws_securityhub_finding_aggregator"
  res.values.linking_mode == "NO_REGIONS"
}
