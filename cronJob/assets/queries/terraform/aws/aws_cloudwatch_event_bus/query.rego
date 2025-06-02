package kics

__rego_meta__ = {"id": "AWS005","version": "1.0","name": "EventBridge dead_letter_config uses unencrypted SQS queue","severity": "HIGH","type": "VULNERABILITY","description": "Ensures dead_letter_config for aws_cloudwatch_event_bus references an encrypted SQS queue."}

violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_cloudwatch_event_bus"
  after := resource.change.after
  config := after.dead_letter_config[0]
  startswith(config.arn, "arn:aws:sqs:")
  not contains(config.arn, ":alias/aws/kms")
}
