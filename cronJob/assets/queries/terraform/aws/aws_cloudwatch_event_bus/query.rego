package main

import data.terraform.tfplan.v2 as tfplan

violation[{{"msg": msg}}] {
  resource := tfplan.resource_changes[_]
  resource.type == "aws_cloudwatch_event_bus"
  config := resource.change.after
  config.dead_letter_config
  arn := config.dead_letter_config.queue_arn
  re_match(".*\\*.*", arn)
  msg := sprintf("Dead letter queue ARN uses a wildcard, which may route events to unintended queues: %s", [arn])
}