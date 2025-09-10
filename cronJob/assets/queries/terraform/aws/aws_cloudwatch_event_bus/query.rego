package terraform.aws.dead_letter_config

# Detects AWS CloudWatch Event Bus with a dead_letter_config pointing to an unencrypted SQS queue
violation[eventbus] {
  resource := tfplan.resource_changes[_]
  resource.type == "aws_cloudwatch_event_bus"
  after := resource.change.after
  dlc := after.dead_letter_config
  dlc != null
  arn := dlc[0].target_arn
  startswith(arn, "arn:aws:sqs")
  queue := tfplan.resource_changes[_]
  queue.type == "aws_sqs_queue"
  queue.name == basename(arn)
  not queue.change.after.server_side_encryption
  eventbus := sprintf("EventBus '%s' uses unencrypted DLQ %s", [resource.name, arn])
}