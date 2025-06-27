package terraform.security.aws

violation[{
  "resource": resource.address,
  "message": msg
}] {
  resource := input.resource_changes[_]
  resource.type == "aws_ecs_account_setting_default"
  resource.change.after.name == "defaultLogDriverMode"
  resource.change.after.value == "non-blocking"
  msg := sprintf("ECS account defaultLogDriverMode is set to non-blocking. This may cause log loss and hamper auditing.", [])
}