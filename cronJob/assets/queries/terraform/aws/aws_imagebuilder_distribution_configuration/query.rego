package kics

# Checks that aws_imagebuilder_distribution_configuration sets a KMS key for SSM parameter configuration to avoid unencrypted storage
violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_imagebuilder_distribution_configuration"
  after := resource.change.after.distribution[_]
  config := after.ssm_parameter_configuration
  # If ssm_parameter_configuration is present but no kms_key_id provided
  config != null
  not config.kms_key_id
  resource
}