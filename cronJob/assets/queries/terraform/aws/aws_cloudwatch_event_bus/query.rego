package kics

import data.terraform as tf

violation[{"msg": msg, "resource": resource}] {
  resource := tf.resource.aws_cloudwatch_event_bus[_]
  resource.values.dead_letter_config
  not resource.values.dead_letter_config.kms_key_arn
  msg := "Dead letter configuration for AWS CloudWatch Event Bus is not encrypted with a KMS key."
}