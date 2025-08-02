package main

__rego_meta__ = {
  "id": "AWSMONITORING_60",
  "title": "Ensure dead_letter_config on aws_cloudwatch_event_bus uses an encrypted SQS queue",
  "severity": "HIGH",
  "type": "VULNERABILITY"
}

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_cloudwatch_event_bus"
  dead_letter := resource.change.after.dead_letter_config
  dead_letter
  queue_arn := dead_letter[0].target_queue_arn
  not encrypted_queue(queue_arn)
  msg := sprintf("Dead letter queue '%s' is not encrypted, which may expose event data", [queue_arn])
}

encrypted_queue(queue_arn) {
  sqs := input.resource_changes[_]
  sqs.type == "aws_sqs_queue"
  sqs.change.after.arn == queue_arn
  sqs.change.after.kms_master_key_id
}