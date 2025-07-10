package main

__rego_metadata__ = {
  "id": "AWS0021",
  "title": "AWS CloudWatch Event Bus dead_letter_config should use encrypted SQS queue",
  "severity": "HIGH",
  "type": "misconfiguration",
}

violation[{
  "Resource": address,
  "Message": msg,
}] {
  resource := input.resource_changes[_].change.after
  resource.type == "aws_cloudwatch_event_bus"
  configs := resource.values.dead_letter_config
  count(configs) > 0
  queueArn := configs[0].queue_arn
  # Imaginary: encrypted queues must include '-encrypted-' in ARN
  not contains(queueArn, "-encrypted-")
  address := resource.address
  msg := sprintf("Dead letter queue '%s' is not encrypted.", [queueArn])
}