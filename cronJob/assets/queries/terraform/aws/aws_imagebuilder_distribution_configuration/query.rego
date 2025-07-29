package main

violation[resource] {
  resource := input.resource
  resource.type == "aws_imagebuilder_distribution_configuration"
  distribution := resource.values.distribution[_]
  ssm := distribution.ssm_parameter_configuration
  ssm.type != "SecureString"
}