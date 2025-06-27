package terraform.aws_imagebuilder_distribution_configuration

violation[{"resource": resource}] {
  resource := tfplan.resource_changes[_]
  resource.type == "aws_imagebuilder_distribution_configuration"
  after := resource.change.after
  distributions := after.distribution
  config := distributions[_].ssm_parameter_configuration
  name := config.parameter_name
  not startswith(name, "/private")
}