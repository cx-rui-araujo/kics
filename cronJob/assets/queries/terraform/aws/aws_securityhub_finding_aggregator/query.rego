package terraform.securityhub

__rego_metadata__ := {"id": "AWS_SH_01", "title": "Security Hub Finding Aggregator should not use NO_REGIONS", "type": "terraform", "severity": "HIGH", "description": "Using NO_REGIONS in linking_mode will not aggregate any regions, possibly missing security findings.", "source": "custom"}

violation[{"msg": msg, "resource": resource.address}] {
  resource := input.resource
  resource.type == "aws_securityhub_finding_aggregator"
  resource.values.linking_mode == "NO_REGIONS"
  msg := sprintf("Resource '%s' has linking_mode set to NO_REGIONS, aggregating no regions", [resource.address])
}
