package main

__rego_metadata__ := {"id": "KICS-123","title": "CloudWatch Event Bus Dead Letter Queue should be encrypted","severity": "HIGH","type": "VULNERABILITY","enabled": true}

denied[msg] {
  rc := input.resource_changes[_]
  rc.type == "aws_cloudwatch_event_bus"
  after := rc.change.after
  dlq := after.dead_letter_config
  dlq != null
  not queue_encrypted(dlq.arn)
  msg := sprintf("%v: Dead letter queue %v is not encrypted", [rc.address, dlq.arn])
}

queue_encrypted(arn) {
  sqs := input.resources[_]
  sqs.type == "aws_sqs_queue"
  sqs.values.arn == arn
  sqs.values.kms_master_key_id != ""
}