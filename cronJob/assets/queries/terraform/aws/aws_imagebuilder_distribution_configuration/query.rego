package terraform

__rego_metadata__ = {
  "id": "AWS_IMAGEBUILDER_SSM_SECURESTRING",
  "title": "Ensure SSM Parameter uses SecureString in Imagebuilder Distribution Configuration",
  "severity": "HIGH",
  "type": "Best Practice",
  "affected_resources": ["aws_imagebuilder_distribution_configuration"]
}

deny[message] {
  resource := input.resource_changes["aws_imagebuilder_distribution_configuration"][_]
  after := resource.change.after
  distribution := after.distribution[_]
  ssm := distribution.ssm_parameter_configuration
  ssm.parameter_type != "SecureString"
  message := sprintf("Resource '%v' has insecure SSM parameter type '%v', use 'SecureString'", [resource.address, ssm.parameter_type])
}