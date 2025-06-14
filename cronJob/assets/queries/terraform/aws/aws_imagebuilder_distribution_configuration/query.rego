package terraform.aws

violation[issue] {
  resource := input.resource_changes[_]
  resource.type == "aws_imagebuilder_distribution_configuration"
  after := resource.change.after
  distribution := after.distribution[_]
  param := distribution.ssm_parameter_configuration
  param != null
  not param.kms_key_id
  issue := {
    "message": "SSM parameter configuration should specify a KMS key for encryption",
    "resource": resource.address
  }
}