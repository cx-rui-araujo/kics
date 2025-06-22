package terraform.aws.cloudwatch_event_bus

violation[dead_letter] {
  bus := input.resource_changes[_]
  bus.type == "aws_cloudwatch_event_bus"
  dlc := bus.change.after.dead_letter_config
  dlc != null
  queue_arn := dlc[0].arn
  # Ensure the dead letter queue is in the same AWS account as the CloudWatch Event Bus
  not regex.match(`^arn:aws:sqs:[\w-]+:\d{12}:[\w-]+$`, queue_arn)
  dead_letter := {
    "resource": bus.address,
    "message": sprintf("aws_cloudwatch_event_bus '%v' configures a cross-account or invalid SQS ARN for dead_letter_config: %v", [bus.address, queue_arn])
  }
}