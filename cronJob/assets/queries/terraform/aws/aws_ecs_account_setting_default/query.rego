package kics

# Detect insecure defaultLogDriverMode that may drop logs leading to audit gaps
deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_ecs_account_setting_default"
  resource.change.after.Name == "defaultLogDriverMode"
  resource.change.after.Value == "non-blocking"
  msg := sprintf("Insecure defaultLogDriverMode set to '%s', logs may be lost or not collected, leading to audit gaps.", [resource.change.after.Value])
}