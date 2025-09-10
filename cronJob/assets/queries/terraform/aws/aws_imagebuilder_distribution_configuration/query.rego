package terraform.security

# KICS query to detect aws_imagebuilder_distribution_configuration resources
# that define ssm_parameter_configuration without specifying a kms_key_id

violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_imagebuilder_distribution_configuration"

  # Iterate over distribution blocks
  after := resource.change.after
  dist := after.distribution[_]

  # ssm_parameter_configuration is present
  config := dist.ssm_parameter_configuration
  config

  # kms_key_id is not set or empty
  not config.kms_key_id

  resource
}