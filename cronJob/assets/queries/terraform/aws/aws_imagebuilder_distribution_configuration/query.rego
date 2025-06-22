package imagebuilder

__rego_metadata__ := {"id": "AWSImageBuilderDistributionSSMParameterNoKMS", "title": "SSM Parameter Configuration without KMS", "description": "AWS Imagebuilder distribution configuration should specify a KMS key for SSM parameter configuration to ensure encryption at rest.", "severity": "HIGH", "category": "Encryption", "version": "1.0.0"}

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_imagebuilder_distribution_configuration"
  after := resource.change.after
  distribution := after.distribution[_]
  ssm := distribution.ssm_parameter_configuration
  ssm != null
  not ssm.kms_key_id
  msg := sprintf("SSM parameter configuration for AWS Imagebuilder distribution '%s' should specify a kms_key_id", [after.name])
}