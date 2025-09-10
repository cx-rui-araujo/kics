package main

__rego_metadata__ := {
  "id": "KICS-AWS-CCEC-1",
  "title": "Ensure aws_cloudwatch_event_connection uses a customer-managed KMS key",
  "severity": "MEDIUM",
  "category": "Encryption",
  "technology": "Terraform",
  "description": "CloudWatch Event Connections without a specified customer-managed KMS key use AWS-managed keys by default, which may not meet compliance requirements.",
  "source": "custom"
}

violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_cloudwatch_event_connection"
  after := resource.change.after
  not after.kms_key_identifier
  resource_address := resource.address
  resource := {
    "resource": resource_address,
    "message": "Missing customer-managed KMS key identifier for CloudWatch Event Connection"
  }
}