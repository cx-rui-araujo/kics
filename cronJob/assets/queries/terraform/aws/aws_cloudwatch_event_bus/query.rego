package main

violation[resource] {
  resource := terraform.aws_cloudwatch_event_bus[_]
  # Flag when a dead_letter_config is set without enforcing encryption on the target SQS queue
  resource.value.dead_letter_config
}