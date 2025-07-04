package main

__rego_metadata__ := {
  "id": "KICS-IMAGEBUILDER-001",
  "title": "SSM Parameter configuration in ImageBuilder distribution should use encryption",
  "short_description": "An SSM Parameter configuration without an encryption_key_id may expose plaintext data in Parameter Store.",
  "severity": "HIGH",
  "type": "VULNERABILITY",
  "service": "imagebuilder",
  "resource": "aws_imagebuilder_distribution_configuration",
  "recommended_actions": "Specify a valid encryption_key_id in the ssm_parameter_configuration block to encrypt the parameter.",
  "provider": "aws"
}

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_imagebuilder_distribution_configuration"
  after := resource.change.after
  dist := after.distribution[_]
  ssm := dist.ssm_parameter_configuration
  ssm != null
  not ssm.encryption_key_id
  msg := sprintf("ImageBuilder distribution '%s' has ssm_parameter_configuration without encryption_key_id, leading to plaintext SSM parameters", [after.name])
}