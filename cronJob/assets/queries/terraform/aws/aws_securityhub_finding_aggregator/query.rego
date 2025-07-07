package terraform.securityhub

__rego_metadoc__ := {"id": "AWS_SHUB_001", "title": "Security Hub finding aggregator linking_mode set to NO_REGIONS", "severity": "HIGH", "type": "VULNERABILITY"}

deny[resource] {
  resource := input.resource_blocks[_]
  resource.type == "aws_securityhub_finding_aggregator"
  attr := resource.body.attributes.linking_mode
  attr.value == "NO_REGIONS"
}