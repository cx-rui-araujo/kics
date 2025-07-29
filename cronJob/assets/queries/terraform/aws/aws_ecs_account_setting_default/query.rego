package main

# KICS Query: aws_ecs_disable_log_driver
# Severity: HIGH
# Category: Logging
# Description: Prevent disabling of the default ECS log driver via defaultLogDriverMode

import data.terraform.tfplan as tfplan

violation[{
  "msg": msg,
  "resource": res_address
}] {
  resource_changes := tfplan.resource_changes
  change := resource_changes[_]
  change.type == "aws_ecs_account_setting_default"
  after := change.change.after
  after.Name == "defaultLogDriverMode"
  after.Value == "disabled"
  res_address = change.address
  msg = sprintf("Resource '%s' sets defaultLogDriverMode to 'disabled', disabling container logs and risking missing audit data.", [res_address])
}