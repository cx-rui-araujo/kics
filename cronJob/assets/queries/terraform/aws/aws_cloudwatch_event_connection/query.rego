package terraform.rules.aws

__rego_metadata__ := {
  "id": "AWS023",
  "title": "Ensure aws_cloudwatch_event_connection uses a custom KMS key",
  "description": "Not specifying a customer-managed KMS key or using the AWS-managed default key for CloudWatch Event Connections may lead to inadequate encryption controls.",
  "severity": "MEDIUM",
  "service": "cloudwatch",
  "resource": "aws_cloudwatch_event_connection"
}

violation[connection] {
  connection := input.resource_changes[_]
  connection.type == "aws_cloudwatch_event_connection"
  after := connection.change.after
  # Missing custom KMS key
  not after.kms_key_identifier
}

violation[connection] {
  connection := input.resource_changes[_]
  connection.type == "aws_cloudwatch_event_connection"
  kms := connection.change.after.kms_key_identifier
  # Using AWS-managed default key
  startswith(kms, "alias/aws/")
}