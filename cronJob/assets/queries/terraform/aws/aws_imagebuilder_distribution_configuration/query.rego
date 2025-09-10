package terraform.aws_imagebuilder

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_imagebuilder_distribution_configuration"
  after := resource.change.after
n  distributions := after.distribution
  any dist in distributions{
    ssm := dist.ssm_parameter_configuration
    ssm != null
    not ssm.kms_key_id
    msg := "SSM Parameter configuration must specify a KMS key for encryption"
  }
}