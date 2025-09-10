package main

version = "1.0.0"
policy_type = "terraform"
description = "Ensure custom KMS key is used for CloudWatch Event Connection to avoid using AWS managed keys"
resources = ["aws_cloudwatch_event_connection"]
labels = ["security","terraform","encryption"]

violation[resource] {
  resource := input.resource
  resource.type == "aws_cloudwatch_event_connection"
  key := resource.values.kms_key_identifier
  startswith(key, "alias/aws")
}