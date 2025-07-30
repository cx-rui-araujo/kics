package kics

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_imagebuilder_distribution_configuration"
  after := resource.change.after
  dist := after.distribution[_]
  ssm := dist.ssm_parameter_configuration
  ssm != null
  // If no KMS key is provided, parameters are stored unencrypted
  not ssm.key_id
  msg := sprintf("Resource '%s' configures SSM parameter without KMS key (plaintext storage)", [resource.address])
}