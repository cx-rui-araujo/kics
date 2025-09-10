package aws.cloudwatch_event_bus

__rego_metadata__ := {
  "id": "AWS_CW_EVENT_BUS_DQN_ENCRYPTION_CHECK",
  "title": "Ensure dead_letter_config uses encrypted SQS dead-letter queue",
  "severity": "MEDIUM",
  "type": "AWS.Security.Encryption"
}

violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_cloudwatch_event_bus"
  after := resource.change.after
  after.dead_letter_config
  # Imaginary attribute enforcing encryption on the dead-letter queue
  not after.dead_letter_config.kms_master_key_id
}