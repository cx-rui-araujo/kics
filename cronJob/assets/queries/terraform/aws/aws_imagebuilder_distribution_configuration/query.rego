package terraform.security

violation[{"resource": resource.address, "msg": "SSM Parameter Configuration is set and may expose sensitive data"}] {
  resource := input.resource_changes[_]
  resource.type == "aws_imagebuilder_distribution_configuration"
  after := resource.change.after
  distribution := after.distribution[_]
  distribution.ssm_parameter_configuration
}