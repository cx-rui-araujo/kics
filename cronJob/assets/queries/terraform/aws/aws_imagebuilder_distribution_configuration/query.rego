package terraform.aws_imagebuilder_distribution_configuration

__rego_metadata__ := {
  "id": "KICS-0001",
  "queryName": "Ensure SSM parameter configuration uses KMS key",
  "severity": "HIGH",
  "description": "Ensure that the ssm_parameter_configuration includes a KMS key ID to encrypt the parameter value."
}

deny[violation] {
  resource := input.resource_changes[_]
  resource.type == "aws_imagebuilder_distribution_configuration"
  after := resource.change.after
  distribution := after.distribution[_]
  ssm := distribution.ssm_parameter_configuration
  not ssm.kms_key_id
  violation := {
    "resource": resource.address,
    "message": sprintf("Missing 'kms_key_id' in ssm_parameter_configuration for distribution configuration '%s'", [resource.address])
  }
}