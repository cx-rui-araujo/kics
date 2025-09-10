package kics

__rego_metadata__ := {
  "id": "AWS999",
  "title": "ECS defaultLogDriverMode insecure configuration",
  "severity": "MEDIUM",
  "type": "VULNERABILITY",
}

violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_ecs_account_setting_default"
  after := resource.change.after
  after.Name == "defaultLogDriverMode"
  after.Value == "insecure_mode"
  msg := sprintf("Use of insecure defaultLogDriverMode '%s' may expose sensitive logs", [after.Value])
}