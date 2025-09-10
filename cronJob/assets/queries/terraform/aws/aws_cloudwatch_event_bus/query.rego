package main

__rego_metadata__ = {
  "id": "AWS017",
  "title": "Ensure EventBus dead_letter_config uses an encrypted SQS DLQ",
  "severity": "MEDIUM",
  "type": "KICS",
  "category": "encryption",
}

denial[issue] {
  # Find CloudWatch event bus with dead_letter_config
  ev := input.Resources[_]
  ev.Type == "aws_cloudwatch_event_bus"
  dlc := ev.Config.dead_letter_config
  dlc != null

  # Extract the DLQ ARN
  queueArn := dlc.arn

  # Find the SQS queue resource matching the ARN
  sqs := input.Resources[_]
  sqs.Type == "aws_sqs_queue"
  sqs.Config.arn == queueArn

  # Check if the queue is not encrypted with KMS
  not sqs.Config.kms_master_key_id

  issue := sprintf("CloudWatch EventBus '%v' uses dead_letter_config with unencrypted SQS queue '%v'", [ev.Metadata.Name, queueArn])
}