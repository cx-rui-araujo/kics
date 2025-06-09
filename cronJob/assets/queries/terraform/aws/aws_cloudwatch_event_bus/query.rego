package main

violation[{\"resource\": resource.address, \"rule_id\": \"AWS_DEADLETTER_SQS_PUBLIC_ACCESS\", \"msg\": msg}] {
  resource := data.terraform.resources[_]
  resource.type == \"aws_cloudwatch_event_bus\"
  dlq := resource.values.dead_letter_config
  dlq.arn
  startswith(dlq.arn, \"arn:aws:sqs\")
  msg := \"Dead letter queue for CloudWatch Event Bus should not be public to avoid leaks.\"
}