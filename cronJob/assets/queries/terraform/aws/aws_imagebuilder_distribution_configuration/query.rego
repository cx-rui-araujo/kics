package kics

violation[message] {
  resource := input.resource_changes[_]
  resource.type == "aws_imagebuilder_distribution_configuration"
  after := resource.change.after
  distribution := after.distribution
  distribution != null
  ssm := distribution.ssm_parameter_configuration
  ssm != null
  not ssm.key_id
  message := sprintf("Resource %s defines an SSM parameter configuration without kms key encryption", [resource.address])
}