package main

__rego_metadata__ := {
  "id": "KICS-EXAMPLE-1",
  "title": "AWS ImageBuilder Distribution SSM Parameter configuration should include KMS key",
  "severity": "HIGH",
  "type": "VULNERABILITY",
}

deny[resource] {
  resource := input.resources[_]
  resource.type == "aws_imagebuilder_distribution_configuration"
  distribution := resource.values.distribution[_]
  param_conf := distribution.ssm_parameter_configuration
  not param_conf.kms_key_id
}