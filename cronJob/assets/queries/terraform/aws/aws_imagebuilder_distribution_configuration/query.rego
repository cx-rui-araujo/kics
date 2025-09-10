package main

default deny = []

denied[reason] {
  resource := input.resource_changes[_]
  resource.type == "aws_imagebuilder_distribution_configuration"
  after_dist := resource.change.after.distribution[_]
  param := after_dist.ssm_parameter_configuration
  not param.kms_key_id
  reason := sprintf(
    "Resource '%s' defines an SSM parameter configuration without kms_key_id, parameters may be stored unencrypted.",
    [resource.address],
  )
  deny := [reason]
}