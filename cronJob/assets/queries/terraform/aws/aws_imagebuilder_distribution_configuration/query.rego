package kics

violation[{"msg": msg, "resource": resource.address}] {
  resource := input.resource_changes[_]
  resource.type == "aws_imagebuilder_distribution_configuration"

  distribution := resource.change.after.distribution[_]
  ssm := distribution.ssm_parameter_configuration

  # Detect SSM parameters stored without encryption
  ssm.type != "SecureString"
  msg := sprintf("SSM parameter '%s' is stored without encryption, use SecureString", [ssm.ssm_parameter_name])
}