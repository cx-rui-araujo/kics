package terraform.aws.ImageBuilder

violation[resource] {
  resource := input.plan.resource_changes[_]
  resource.type == "aws_imagebuilder_distribution_configuration"
  contains(resource.change.actions, "create")
  distribution := resource.change.after.distribution[_]
  ssm := distribution.ssm_parameter_configuration
  ssm.type == "String"
}