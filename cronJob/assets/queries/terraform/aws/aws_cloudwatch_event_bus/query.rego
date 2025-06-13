package terraform.aws.event_bus

__rego_meta__ = {
  "id": "KICS-aws-cloudwatch-event-bus-dead-letter-config-missing-retries",
  "version": "0.1.0",
  "title": "CloudWatch Event Bus missing retry_attempts in dead_letter_config",
  "severity": "MEDIUM",
  "description": "When using dead_letter_config, retry_attempts should be specified to avoid infinite retry loops."
}

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_cloudwatch_event_bus"
  after := resource.change.after
  after.dead_letter_config
  not after.dead_letter_config.retry_attempts
  msg := sprintf("Resource '%s' is missing 'retry_attempts' in 'dead_letter_config'.", [resource.name])
}