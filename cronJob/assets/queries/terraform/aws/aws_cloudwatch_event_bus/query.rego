package main

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == \"aws_cloudwatch_event_bus\"
  after := resource.change.after
  dead_letter := after.dead_letter_config[0]
  contains(dead_letter.arn, \"*\")
  msg := sprintf(\"Dead letter ARN contains wildcard: %s\", [dead_letter.arn])
}