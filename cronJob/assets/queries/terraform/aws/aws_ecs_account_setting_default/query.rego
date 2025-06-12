package kics

import data

deny[msg] {
  some i
  change := input.resource_changes[i]
  change.type == "aws_ecs_account_setting_default"
  after := change.change.after
  after.Name == "defaultLogDriverMode"
  after.Value == "non-blocking"
  msg = sprintf("Resource '%s' sets defaultLogDriverMode to non-blocking, logs may be lost", [change.address])
}