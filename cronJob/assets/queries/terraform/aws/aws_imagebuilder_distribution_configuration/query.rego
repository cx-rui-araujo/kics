package kics
import data.tfconfig as tfconfig

deny[msg] {
  resource := tfconfig.resource.aws_imagebuilder_distribution_configuration[_]
  distribution := resource.values.distribution[_]
  param := distribution.ssm_parameter_configuration
  not param.kms_key_id
  msg := {
    "resource": resource.address,
    "message": "SSM parameter configuration should include a KMS key_id to encrypt sensitive data."
  }
}