package kics

# Detect aws_imagebuilder_distribution_configuration resources using ssm_parameter_configuration
violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_imagebuilder_distribution_configuration"
  after := resource.change.after
  dist := after.distribution[_]
  dist.ssm_parameter_configuration
}