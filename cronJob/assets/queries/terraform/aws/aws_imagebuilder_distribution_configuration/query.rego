package kics

import input

__rego_metadata__ := {
  "id": "AWS_IMAGEBUILDER_DISTRIBUTION_SSM_SECURESTRING",
  "title": "SSM Parameter type should be SecureString",
  "severity": "MEDIUM",
  "type": "terraform",
  "metadata": {
    "description": "Ensures that Image Builder distribution SSM parameters use SecureString to avoid storing secrets in plaintext.",
    "recommendedActions": "Set the 'type' field in ssm_parameter_configuration to 'SecureString'."
  }
}

deny[resource] {
  resource := input.resource
  resource.type == "aws_imagebuilder_distribution_configuration"
  dist := resource.config.distribution[0]
  ssm := dist.ssm_parameter_configuration[0]
  ssm.type != "SecureString"
}