package tf_aws_ecs_account_setting_default

# Avoid disabling ECS log driver by setting defaultLogDriverMode to 'none'
violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_ecs_account_setting_default"
  resource.change.after.Name == "defaultLogDriverMode"
  resource.change.after.Value == "none"
}