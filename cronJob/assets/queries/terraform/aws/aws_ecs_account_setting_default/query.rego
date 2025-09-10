package aws_ecs_account_setting_default

default_non_blocking_log_driver_mode_violation[msg] {
  # Locate the Terraform plan resource change for aws_ecs_account_setting_default
  rc := input.resource_changes[_]
  rc.type == "aws_ecs_account_setting_default"

  # Check if the Name argument is defaultLogDriverMode and the value is non-blocking
  rc.change.after.name == "defaultLogDriverMode"
  rc.change.after.value == "non-blocking"

  msg := sprintf("ECS account setting '%v' uses non-blocking log driver mode, which can lead to log loss and hinder auditing", [rc.change.after.value])
}