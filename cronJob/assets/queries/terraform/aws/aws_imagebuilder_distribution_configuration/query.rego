package terraform

deny[msg] {
  resource := tfplan.resource_changes[_]
  resource.type == "aws_imagebuilder_distribution_configuration"
  after := resource.change.after
  dist := after.distribution[0]
  ssm := dist.ssm_parameter_configuration[0]
  ssm.parameter_type != "SecureString"
  msg := sprintf("aws_imagebuilder_distribution_configuration '%s' uses non-encrypted SSM parameter type '%s'; ensure 'SecureString' for sensitive data", [resource.address, ssm.parameter_type])
}