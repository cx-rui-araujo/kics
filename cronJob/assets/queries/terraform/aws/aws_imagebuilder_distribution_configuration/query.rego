package main

__rego_metadata__ = {"id": "TF_AWS_IMAGEBUILDER_SSM_ENCRYPTION","title": "Ensure SSM parameters are encrypted","severity": "HIGH","type": "VULNERABILITY"}

violation[msg] {
  resource := input.resource
  resource.type == "aws_imagebuilder_distribution_configuration"
  distribution := resource.values.distribution[0]
  ssm := distribution.ssm_parameter_configuration
  not ssm.key_id
  msg := sprintf("Resource '%s': distribution.ssm_parameter_configuration.key_id must be set to encrypt SSM parameters.", [resource.address])
}
