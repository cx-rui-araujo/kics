package main

__rego_metadoc__ := {"id": "KICS-9999","title": "Ensure dead letter queue is encrypted with a KMS key","severity": "MEDIUM","type": "ENCRYPTION"}

violation[{
  "msg": msg,
  "resource": resource_name
}] {
  resource := input.resource["aws_cloudwatch_event_bus"]
  resource_name := resource.metadata.name
  dead_letter := resource.config.dead_letter_config
  dead_letter != null
  dead_letter.kms_key_arn == null
  msg := sprintf("CloudWatch Event Bus '%s' configures dead_letter_config without kms_key_arn (unencrypted)", [resource_name])
}