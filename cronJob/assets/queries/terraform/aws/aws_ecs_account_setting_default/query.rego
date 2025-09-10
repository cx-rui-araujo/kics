package main

__rego_metadata__ := {
  "id": "KICS-0001",
  "title": "ECS default log driver mode should be blocking",
  "severity": "MEDIUM",
  "type": "Misconfiguration",
}

violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_ecs_account_setting_default"
  after := resource.change.after
  after.Name == "defaultLogDriverMode"
  after.Value != "blocking"
}