package aws.imagebuilder

deny_ssm_parameter_unencrypted[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_imagebuilder_distribution_configuration"
  after := resource.change.after
  dist := after.distribution[_]
  ssm := dist.ssm_parameter_configuration
  not ssm.kms_key_id
  msg := sprintf("ImageBuilder distribution '%s' has an SSM parameter configuration without a KMS key ID; parameters will be stored unencrypted.", [resource.address])
}