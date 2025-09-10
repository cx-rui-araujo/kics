package kics

__rego_metadata__ := {"id": "AWS_IMAGEBUILDER_DISTRIBUTION_SSM_ENCRYPTION", "title": "Ensure SSM Parameter Configuration uses KMS encryption", "severity": "HIGH"}

violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_imagebuilder_distribution_configuration"
  dist := resource.change.after.distribution[_]
  dist.ssm_parameter_configuration
  not dist.ssm_parameter_configuration.key_arn
}