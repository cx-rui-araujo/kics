package main

# Detect aws_imagebuilder_distribution_configuration with SSM parameter config lacking KMS encryption
violation[res] {
  resource := input.resource_changes[_]
  resource.type == "aws_imagebuilder_distribution_configuration"
  # Check after-change data
  after := resource.change.after
  dist := after.distribution[_]
  ssm := dist.ssm_parameter_configuration
  ssm != null
  # kms_key_id must not be empty or missing
  (ssm.kms_key_id == "" or not ssm.kms_key_id)
  res := {
    "resource": resource.address,
    "message": "SSM parameter configuration is missing kms_key_id for encryption"
  }
}