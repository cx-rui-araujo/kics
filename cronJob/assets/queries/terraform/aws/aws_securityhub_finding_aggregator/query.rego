package main

__rego_metadata__ = {
  "id": "KICS-AGGR-001",
  "title": "Avoid NO_REGIONS for linking_mode in aws_securityhub_finding_aggregator",
  "severity": "MEDIUM",
  "category": "Misconfiguration"
}

violation[resource] {
  resource := input.resource.aws_securityhub_finding_aggregator[_]
  resource.values.linking_mode == "NO_REGIONS"
}