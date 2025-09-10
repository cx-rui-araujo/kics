package main

__rego_metadata__ = {
  "id": "CUSTOM_AWS_IMAGEBUILDER_SSM_SECURESTRING",
  "title": "Ensure imagebuilder distribution SSM parameter uses SecureString",
  "severity": "LOW",
  "type": "terraform",
}

violation[issue] {
  resource := input.resource_changes[_]
  resource.type == "aws_imagebuilder_distribution_configuration"
  after := resource.change.after
  some i
  param := after.distribution[i].ssm_parameter_configuration
  param
  not param.parameter_type == "SecureString"
  issue := {
    "message": sprintf("SSM parameter configuration '%s' is of type '%s', not SecureString", [param.parameter_name, param.parameter_type]),
    "resource": resource.address
  }
}
