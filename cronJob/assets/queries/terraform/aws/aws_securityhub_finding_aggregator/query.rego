package main

__rego_metadata__ = {
  "id": "KICS_AWS_SECURITYHUB_FINDING_AGG_1",
  "version": "1.0.0",
  "title": "Avoid NO_REGIONS for SecurityHub Finding Aggregator",
  "description": "Using NO_REGIONS for linking_mode can lead to unmonitored new regions.",
  "severity": "MEDIUM",
  "recommended_actions": ["Set linking_mode to ALL_REGIONS or SPECIFIED_REGIONS to ensure coverage."]
}

violation[{
  "msg": msg,
  "resource": address
}] {
  resource := tfplan.resource_changes["aws_securityhub_finding_aggregator"][i]
  address := resource.address
  resource.change.after.linking_mode == "NO_REGIONS"
  msg := sprintf("Resource %s uses linking_mode 'NO_REGIONS', which may leave new regions unmonitored", [address])
}