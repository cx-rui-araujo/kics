package terraform.aws.CloudWatchEventBusDeadLetterConfig

# KICS query to ensure dead_letter_config is defined on aws_cloudwatch_event_bus
violation[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_cloudwatch_event_bus"
  # after applying changes, dead_letter_config block must exist
  not resource.change.after.dead_letter_config
  msg = sprintf("aws_cloudwatch_event_bus '%s' does not define dead_letter_config, failed events may be lost.", [resource.change.after.name])
}