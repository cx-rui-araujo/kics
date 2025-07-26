package tfsec

# Ensure distribution.ssm_parameter_configuration includes encryption_key_id to avoid unencrypted SSM parameters

deny[msg] {
  resource := tfconfig.resource_types.aws_imagebuilder_distribution_configuration.resources[_]
  distribution := resource.values.distribution[_]
  # SSM parameter configuration block exists
  distribution.ssm_parameter_configuration
  # encryption_key_id is missing or empty
  not distribution.ssm_parameter_configuration.encryption_key_id
  msg := sprintf("Resource '%s' missing encryption_key_id in ssm_parameter_configuration", [resource.name])
}