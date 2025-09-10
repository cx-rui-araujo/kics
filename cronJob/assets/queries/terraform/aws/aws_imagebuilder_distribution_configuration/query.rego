package kics

__rego_metadata__ = {
  "id": "KICS-999",
  "title": "Ensure AWS Imagebuilder distribution SSM parameters use KMS encryption",
  "severity": "HIGH",
  "type": "VIOLATION"
}

violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_imagebuilder_distribution_configuration"
  dist := resource.change.after.distribution[_]
  cfg := dist.ssm_parameter_configuration
  not cfg.kms_key_id
}