package terraform.aws.cloudwatch_event_bus

import data.terraform as tf

# AWS CloudWatch Event Bus dead-letter queue must be encrypted
violation[resource] {
  resource := tf.resource.aws_cloudwatch_event_bus[name]
  resource.dead_letter_config
  # Ensure KMS encryption is specified for the dead-letter queue
  not resource.dead_letter_config[0].kms_key_arn
}