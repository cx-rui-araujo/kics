package main

__rego_metadata__ := {
  "id": "AWSImagebuilderDistributionConfigurationSSMParameterEncryption",
  "severity": "HIGH",
  "type": "VIOLATION",
  "title": "SSM Parameter Configuration without KMS key",
  "description": "The aws_imagebuilder_distribution_configuration resource defines ssm_parameter_configuration without a kms_key_id, exposing sensitive data at rest.",
  "recommendation": "Add a kms_key_id to distribution.ssm_parameter_configuration to ensure parameters are encrypted.",
  "reference": "https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_PutParameter.html",
  "version": "1.0"
}

denied[result] {
  resource := input.resource_changes[_]
  resource.type == "aws_imagebuilder_distribution_configuration"
  after := resource.change.after
  dist := after.distribution[_]
  ssm := dist.ssm_parameter_configuration
  ssm != null
  not ssm.kms_key_id
  result := {
    "resource": resource.address,
    "message": "SSM parameter configuration is missing kms_key_id for encryption"
  }
}