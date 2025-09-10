package kics

__rego_metadoc__ := {
  "id": "KICS-AWS-999",
  "title": "Ensure custom KMS key identifier is set for aws_cloudwatch_event_connection",
  "severity": "MEDIUM",
  "description": "CloudWatch Event Connections should use a custom KMS key for credential encryption.",
  "recommended_actions": ["Define a custom kms_key_identifier argument"]
}

deny[msg] {
  resource := input.resource_blocks[_]
  resource.type == "aws_cloudwatch_event_connection"
  not resource.attributes.kms_key_identifier
  msg := sprintf("Resource '%s' should have a custom kms_key_identifier defined.", [resource.labels[0]])
}