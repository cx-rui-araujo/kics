package terraform.aws.CloudWatchEventBus

__rego_metadata__ := {
  "id": "AWS.CloudWatchEventBus.EnableDeadLetterConfigEncryption",
  "version": "1.0.0",
  "title": "Ensure CloudWatch Event Bus dead_letter_config has KMS encryption",
  "severity": "MEDIUM",
  "type": "SCALABILITY",
}

deny[res] {
  resource := input.resource_changes[_]
  resource.type == "aws_cloudwatch_event_bus"
  after := resource.change.after
  # Dead letter config is defined
  after.dead_letter_config
  # Missing kms_key_arn for encryption
  not after.dead_letter_config[0].kms_key_arn
  res := {
    "message": sprintf("Dead letter config for CloudWatch Event Bus '%s' does not specify a KMS key for encryption", [resource.address]),
    "resource": resource.address,
  }
}