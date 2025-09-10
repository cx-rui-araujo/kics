package main

# KICS query to ensure an SSM parameter used for distribution is encrypted with a customer-managed KMS key
violation[resource] {
  resource := input.resource
  resource.type == "aws_imagebuilder_distribution_configuration"
  # Check if distribution block exists
  dist := resource.values.distribution[_]
  # Check if ssm_parameter_configuration block is defined
  ssm := dist.ssm_parameter_configuration
  ssm
  # Flag if no kms_key_id is provided
  not ssm.kms_key_id
}