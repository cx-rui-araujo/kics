package main

__rego_metadata__ := {
  "id": "KICS-AWS-999",
  "title": "Ensure CloudWatch Event Bus Dead Letter Config is not misconfigured",
  "description": "A dead_letter_config on CloudWatch Event Bus can forward failed events to unauthorized or unencrypted endpoints if misconfigured.",
  "severity": "MEDIUM",
  "category": "Misconfiguration",
}

violation[resource] {
  resource := input.resource
  resource.type == "aws_cloudwatch_event_bus"
  # Flag any use of dead_letter_config, ensure encryption or proper authorization is enforced separately
  resource.values.dead_letter_config
}