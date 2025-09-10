package terraform.securityhub

__rego_metadata__ := {"id": "KICS_TF_AWS_110","title": "Avoid NO_REGIONS for aws_securityhub_finding_aggregator linking_mode","severity": "MEDIUM","type": "MISCONFIGURATION","reference_id": "AWS.SSH.001"}

violation[resource] {
  resource := input.resource_blocks[_]
  resource.type == "aws_securityhub_finding_aggregator"
  resource.attributes.linking_mode.value == "NO_REGIONS"
}