package terraform.aws.CloudWatchEventBus

import data.kics

violation[res] {
  resource := input.resource_changes[_]
  resource.type == "aws_cloudwatch_event_bus"
  after := resource.change.after
  after.dead_letter_config != null
  dlq := after.dead_letter_config[0]
  # Check that the DLQ ARN is not pointing to a queue outside the current AWS account
  not startswith(dlq.arn, sprintf("arn:aws:sqs:%s:%s:", [data.kics.meta.region, data.kics.meta.account_id]))
  res := {
    "msg": sprintf("Dead-letter queue ARN %s is not in the same AWS account, potential exposure of failed events", [dlq.arn]),
    "resource": resource.address
  }
}