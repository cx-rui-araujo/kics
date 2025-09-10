package terraform.analysis

# Ensure that SSM Parameter Configuration for Imagebuilder Distribution is encrypted

default deny = false

deny[msg] {
  resource := tfconfig.resource.aws_imagebuilder_distribution_configuration
  distribution := resource.values.distribution[_]
  ssm := distribution.ssm_parameter_configuration
  ssm != null
  # encryption_key_id must be set to ensure SSM parameter is encrypted
  not ssm.encryption_key_id
  msg := sprintf("AWS Imagebuilder Distribution '%s' defines ssm_parameter_configuration without encryption_key_id, which may expose parameters in plaintext.", [resource.address])
}