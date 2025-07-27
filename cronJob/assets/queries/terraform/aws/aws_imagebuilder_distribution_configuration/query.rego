package terraform.aws.imagebuilder

__rego_metadata__ := {
  "id": "AWS_IMAGEBUILDER_SSM_PARAM_ENCRYPTION_MISSING",
  "title": "SSM Parameter Configuration Missing Encryption",
  "severity": "HIGH",
  "category": "Encryption"
}

deny[info] {
  resource := input.resource_changes[_]
  resource.type == "aws_imagebuilder_distribution_configuration"
  after := resource.change.after
  distribution := after.distribution[_]
  ssm := distribution.ssm_parameter_configuration
  # Detect use of SSM parameter without specifying an encryption key
  ssm.parameter_name != null
  not ssm.encryption_key_id
  info := {
    "message": sprintf("aws_imagebuilder_distribution_configuration '%s' defines ssm_parameter_configuration without encryption_key_id", [resource.address])
  }
}