package main

deny[res] {
  resource := input.resource
  resource.type == "aws_imagebuilder_distribution_configuration"
  dist := resource.values.distribution[0]
  config := dist.ssm_parameter_configuration[0]
  config.type != "SecureString"
  res = {
    "message": sprintf("SSM parameter configuration uses insecure type '%v'; must be SecureString", [config.type]),
    "resource": resource.id
  }
}