package terraform.imagebuilder.distribution

violation[res] {
  resource := input.resource
  resource.Type == "aws_imagebuilder_distribution_configuration"
  dist := resource.Config.distribution[_]
  ssm := dist.ssm_parameter_configuration
  ssm.type != "SecureString"
  res := {
    "message": sprintf("SSM parameter configuration type '%s' is not SecureString", [ssm.type]),
    "resource": resource
  }
}