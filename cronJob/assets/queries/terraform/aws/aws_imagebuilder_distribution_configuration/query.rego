package terraform

__rego_metadata__ := {
  "id": "AWS0001",
  "title": "Ensure SSM Parameter Configuration uses SecureString",
  "severity": "HIGH",
  "category": "Misconfiguration",
}

violation[res] {
  # Find aws_imagebuilder_distribution_configuration resources
  resource := input.Blocks[_]
  resource.Type == "resource"
  resource.Labels[0] == "aws_imagebuilder_distribution_configuration"

  # Navigate into distribution blocks
  distribution := resource.Body.Blocks[_]
  distribution.Type == "distribution"

  # Navigate into ssm_parameter_configuration blocks
  ssm := distribution.Body.Blocks[_]
  ssm.Type == "ssm_parameter_configuration"

  # Check the parameter_type attribute
  param := ssm.Body.Attributes["parameter_type"]
  param.Value != "SecureString"

  res := {
    "resource": sprintf("%s.%s", [resource.Labels[0], resource.Labels[1]]),
    "message": sprintf("SSM parameter configuration uses '%s' instead of 'SecureString'", [param.Value])
  }
}