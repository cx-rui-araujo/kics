package KICS

__rego_metadata__ := {
  "id": "KICS-9999",
  "title": "AWS Imagebuilder Distribution Configuration SSM parameter without encryption",
  "description": "SSM parameter configuration should specify a KMS key_id for encryption to avoid plaintext storage.",
  "severity": "MEDIUM",
  "recommended_actions": "Specify a KMS key_id in ssm_parameter_configuration to encrypt the parameter."
}

violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_imagebuilder_distribution_configuration"
  after := resource.change.after
  distribution := after.distribution[_]
  ssm := distribution.ssm_parameter_configuration
  not ssm.key_id
}