package terraform.aws.imagebuilder

violation[res] {
  res := input.resource[_]
  res.type == "aws_imagebuilder_distribution_configuration"
  inst := res.instances[_]
  dist := inst.attributes.distribution[0]
  ssm := dist.ssm_parameter_configuration[0]
  ssm.type == "String"
}