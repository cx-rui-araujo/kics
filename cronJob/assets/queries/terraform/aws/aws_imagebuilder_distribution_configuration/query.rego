package main

# Detect aws_imagebuilder_distribution_configuration with ssm_parameter_configuration lacking kms_key_id
ssm_parameter_without_kms[resource] {
  resource := input.resource_blocks.aws_imagebuilder_distribution_configuration[_]
  distribution := resource.block.get_blocks("distribution")[_]
  ssm := distribution.block.get_blocks("ssm_parameter_configuration")[_]
  not ssm.block.has_key("kms_key_id")
  resource
}