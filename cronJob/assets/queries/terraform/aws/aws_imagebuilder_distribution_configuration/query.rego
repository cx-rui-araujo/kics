package main

__rego_metadata__
id = "AWS_IMAGEBUILDER_SSM_1"
title = "Ensure kms_key_id is specified in ssm_parameter_configuration"
description = "Ensure SSM Parameter Configuration for Imagebuilder uses a customer-managed CMK to encrypt the parameter."
severity = "MEDIUM"
__rego_input__

violation[res] {
  input.resource_changes[_].type == "aws_imagebuilder_distribution_configuration"
  after := input.resource_changes[_].change.after
  distribution := after.distribution[_]
  ssm := distribution.ssm_parameter_configuration
  not ssm.kms_key_id
  res := {
    "msg": sprintf("Resource '%s' does not specify kms_key_id in ssm_parameter_configuration", [after.name]),
    "range": []
  }
}