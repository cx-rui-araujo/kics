package main

violation[res] {
  resource := input.resource_instances[_]
  resource.type == "aws_imagebuilder_distribution_configuration"
  dist := resource.attributes.distribution
  ssm := dist["ssm_parameter_configuration"]
  ssm
  not ssm["key_id"]
  res := {
    "msg": sprintf("Resource %s: ssm_parameter_configuration missing key_id; AMI IDs may be stored unencrypted", [resource.address])
  }
}
