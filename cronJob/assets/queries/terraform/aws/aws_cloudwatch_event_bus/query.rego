package terraform.aws.cloudwatch_eventbus

__rego_metadata__ = {
  "id": "AWS099",
  "title": "CloudWatch EventBus with dead_letter_config must enable kms_key_arn",
  "severity": "HIGH",
  "type": "VIOLATION",
  "category": "Security",
  "platform": "Terraform"
}

violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_cloudwatch_event_bus"
  after := resource.change.after
  after.dead_letter_config
  not after.kms_key_arn
}