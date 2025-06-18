package main

__rego_metadata__ := {
  "id": "AWS020",
  "version": "1.0",
  "title": "CloudWatch Event Connection without KMS encryption",
  "description": "Ensures that aws_cloudwatch_event_connection resources specify a customer-managed KMS key.",
  "severity": "HIGH",
  "type": "VIOLATION",
  "labels": {"category": "encryption"},
}

deny[message] {
  resource := input.resource_changes[_]
  resource.type == "aws_cloudwatch_event_connection"
  not resource.change.after.kms_key_identifier
  message := sprintf("Resource '%s' does not specify kms_key_identifier, leaving data unencrypted", [resource.address])
}