package terraform.aws.ecs

disable_logging_violation[message] {
  resource := input.resource_changes[_]
  resource.type == "aws_ecs_account_setting_default"
  after := resource.change.after
  after.Name == "defaultLogDriverMode"
  after.Value == "none"
  message := sprintf("Resource '%s' disables ECS logging by setting defaultLogDriverMode to 'none'", [resource.address])
}