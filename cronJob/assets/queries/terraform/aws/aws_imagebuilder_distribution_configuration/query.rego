package main

__rego_metadata__ = {
  "id": "KICS-TF-9999",
  "title": "Ensure SSM Parameter Configuration uses a customer-managed KMS key",
  "description": "Using the default AWS managed KMS key for SSM parameters may lead to insufficient encryption controls.",
  "severity": "MEDIUM",
  "metadata": {
    "provider": "aws",
    "service": "imagebuilder",
    "recommended_action": "Specify a customer-managed KMS key for SSM parameter configuration"
  }
}

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_imagebuilder_distribution_configuration"
  after := resource.change.after
  dist := after.distribution[_]
  ssm := dist.ssm_parameter_configuration
  not ssm.kms_key_id
  msg := sprintf("Resource '%s' does not specify a kms_key_id for SSM parameter configuration", [resource.address])
}