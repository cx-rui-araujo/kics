package terraform.aws.CloudWatchEventBus

deny[resource] {
  resource := input.resource_blocks[_]
  resource.type == "aws_cloudwatch_event_bus"
  dead_letter := resource.block.dead_letter_config
  dead_letter != null
  not dead_letter.kms_key_arn
}