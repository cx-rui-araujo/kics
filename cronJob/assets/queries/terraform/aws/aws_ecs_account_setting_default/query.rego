package main

__rego_metadata__ := {
  "id": "KICS-1234",
  "title": "Avoid blocking ECS log driver mode",
  "description": "Setting defaultLogDriverMode to blocking can cause containers to pause if logs fill up.",
  "severity": "MEDIUM",
  "type": "VULNERABILITY"
}

violation[resource] {
  resource := input.resource[_]
  resource.type == "aws_ecs_account_setting_default"
  resource.config.Name == "defaultLogDriverMode"
  resource.config.value == "blocking"
}