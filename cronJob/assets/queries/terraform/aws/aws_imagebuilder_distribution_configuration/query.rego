package kics.res.aws_imagebuilder

__rule_metadata__ := {
  "id": "KICS-IB-001",
  "title": "Unencrypted SSM Parameter in Image Builder Distribution",
  "severity": "LOW",
  "type": "VULNERABILITY",
  "description": "SSM parameter configurations should include kms_key_id to ensure encryption."
}

violation[{
  "resource": resource,
  "message": "Missing 'kms_key_id' in distribution.ssm_parameter_configuration, leading to unencrypted SSM parameter creation."
}] {
  resource := input.resource.aws_imagebuilder_distribution_configuration
  distro := resource.distribution[_]
  ssm := distro.ssm_parameter_configuration
  not ssm.kms_key_id
}