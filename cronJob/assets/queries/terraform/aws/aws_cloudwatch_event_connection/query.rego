package terraform_kms_check

__rego_metadata__ := {
  "id": "AWSKMS01",
  "title": "Missing kms_key_identifier for aws_cloudwatch_event_connection",
  "description": "Ensures that aws_cloudwatch_event_connection resources specify a customer-managed KMS key for encryption.",
  "severity": "MEDIUM",
  "terraform_resource": "aws_cloudwatch_event_connection"
}

violation[resource] {
  resource := terraform.resource.aws_cloudwatch_event_connection[_]
  not resource.values.kms_key_identifier
}