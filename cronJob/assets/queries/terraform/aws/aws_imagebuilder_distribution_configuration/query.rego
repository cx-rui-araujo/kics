package main

__rego_metadata__ = {
  "id": "AWS_IMAGEBUILDER_SSM_PARAM_ENCRYPTION_MISSING",
  "title": "Ensure SSM parameter configuration uses encryption",
  "severity": "MEDIUM",
  "type": "VULNERABILITY"
}

deny[msg] {
  resource := data.terraform.resources[_]
  resource.type == "aws_imagebuilder_distribution_configuration"
  distributions := resource.values.distribution
  some idx
  distribution := distributions[idx]
  config := distribution.ssm_parameter_configuration
  config
  not config.kms_key_id
  msg := sprintf("Resource '%v' has SSM parameter configuration without KMS encryption", [resource.address])
}