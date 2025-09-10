package main

__rego_metadata__ := {
  "id": "KICS_AWS_CloudWatch_Event_Connection_KMS",
  "title": "Custom KMS key not specified for CloudWatch Event Connection",
  "severity": "LOW",
  "type": "terraform",
}

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_cloudwatch_event_connection"
  after := resource.change.after
  not after.kms_key_identifier
  msg := sprintf("Resource '%s' does not specify a custom KMS key; default encryption may not meet requirements", [resource.address])
}