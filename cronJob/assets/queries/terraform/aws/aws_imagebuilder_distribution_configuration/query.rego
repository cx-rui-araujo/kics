package main

__rego_metadata__ := {
  "id": "KICS-AWS-IMAGEBUILDER-001",
  "version": "0.1.0",
  "title": "Ensure SSM parameter configuration uses SecureString",
  "severity": "HIGH",
  "type": "MISCONFIGURATION",
  "description": "Ensure that SSM parameter configuration in aws_imagebuilder_distribution_configuration uses SecureString to avoid plaintext secrets.",
  "recommendation": "Set parameter_type to SecureString and specify a KMS key for encryption.",
  "provider": "aws",
  "service": "imagebuilder",
  "resource": "aws_imagebuilder_distribution_configuration"
}

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_imagebuilder_distribution_configuration"
  after := resource.change.after
  distribution := after.distribution[_]
  ssm := distribution.ssm_parameter_configuration[_]
  ssm.parameter_type != "SecureString"
  msg := sprintf("SSM parameter configuration '%s' uses '%s' instead of 'SecureString'", [ssm.parameter_name, ssm.parameter_type])
}