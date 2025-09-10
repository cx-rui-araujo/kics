package terraform.aws_cloudwatch_event_connection

__rego_metadata__ := {
  "id": "AWS999",
  "version": "1.0.0",
  "severity": "HIGH",
  "type": "Terraform Resource Misconfiguration",
  "terraform_resource": "aws_cloudwatch_event_connection",
  "description": "Ensure that `kms_key_identifier` is set to a customer-managed KMS key, not the AWS-managed default key."
}

violation[resource] {
  resource := input.resource.aws_cloudwatch_event_connection[_]
  # Check if kms_key_identifier is missing or using default AWS-managed key alias
  kms := resource.values.kms_key_identifier
  (kms == null) || startswith(kms, "alias/aws")
  resource
}