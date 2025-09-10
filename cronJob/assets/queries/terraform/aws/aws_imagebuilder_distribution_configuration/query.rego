package terraform.aws_imagebuilder

__rego_metadata__ := {
  "id": "KICS-IMG-BUILDER-001",
  "title": "Ensure SSM parameter encryption key ID is specified",
  "severity": "HIGH",
  "type": "Terraform Security Check"
}

violation[{"msg": msg}] {
  resource := input.resource_changes[_]
  resource.type == "aws_imagebuilder_distribution_configuration"
  ssmParam := resource.change.after.distribution.ssm_parameter_configuration
  ssmParam != null
  not ssmParam.key_id
  msg := sprintf("The distribution.ssm_parameter_configuration.key_id is not specified for resource '%s', allowing unencrypted parameters.", [resource.address])
}