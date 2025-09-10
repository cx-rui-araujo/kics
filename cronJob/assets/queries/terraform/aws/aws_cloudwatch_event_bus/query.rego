package resources.aws.cloudwatch_event_bus

__rego_metadata__ := {
  "id": "CKV_AWS_999",
  "title": "Ensure dead-letter queue for CloudWatch event bus is encrypted",
  "severity": "MEDIUM",
  "type": "terraform",
  "provider": "aws"
}

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_cloudwatch_event_bus"
  after := resource.change.after
  after.dead_letter_config != null
  not after.dead_letter_config.kms_key_arn
  msg := sprintf("Dead-letter queue for event bus %s is not encrypted", [resource.address])
}