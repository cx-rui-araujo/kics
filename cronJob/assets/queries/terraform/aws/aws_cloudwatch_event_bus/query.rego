package terraform.kics

violation[message] {
  resource := input.resource_changes[_]
  resource.type == "aws_cloudwatch_event_bus"
  dead := resource.change.after.dead_letter_config
  dead != null
  contains(dead.arn, "arn:aws:sns")
  message := sprintf("Dead letter config uses SNS topic '%s', which may cause recursive event triggers", [dead.arn])
}