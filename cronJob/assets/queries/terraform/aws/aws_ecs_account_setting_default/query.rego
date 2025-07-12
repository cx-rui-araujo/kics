package ecs_account_setting

import data.tfplan

__rego_metadoc__ := {
  "id": "KICS-1234",
  "title": "ECS account default log driver mode non-blocking",
  "severity": "LOW",
  "type": "MISCONFIGURATION",
  "description": "Setting default_log_driver_mode to non-blocking may lead to dropped logs, hindering auditing.",
  "reference_id": "AWS.ECS.AccountSetting.Default.LogDriverMode",
  "platform": "Terraform"
}

deny[msg] {
  rc := data.tfplan.resource_changes[_]
  rc.type == "aws_ecs_account_setting_default"
  mode := rc.change.after.default_log_driver_mode
  mode == "non-blocking"
  msg := sprintf("Resource '%v' sets default_log_driver_mode to non-blocking, logs may be lost", [rc.address])
}