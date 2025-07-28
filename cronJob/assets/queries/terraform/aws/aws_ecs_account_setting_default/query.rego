package terraform.rules

# Detects use of the legacy ECS log driver mode which may expose sensitive data
violation[res] {
  res := input.resource_changes[_]
  res.type == "aws_ecs_account_setting_default"
  after := res.change.after
  after.Name == "defaultLogDriverMode"
  after.Value == "legacy"
}