package main

deny[msg] {
  resource_block := input.resource_blocks.aws_imagebuilder_distribution_configuration[_]
  config := resource_block.block.distribution[0].block.ssm_parameter_configuration
  config.is_present
  config.block.type.attr.value == "String"
  not config.block.kms_key_id
  msg := sprintf("SSM parameter configuration for distribution '%s' uses plaintext storage without KMS encryption", [resource_block.labels[0]])
}