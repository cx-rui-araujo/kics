package main

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_imagebuilder_distribution_configuration"
  distro := resource.change.after.distribution[_]
  ssm := distro.ssm_parameter_configuration
  not ssm.kms_key_id
  msg := sprintf("Resource '%v' missing kms_key_id in ssm_parameter_configuration", [resource.address])
}