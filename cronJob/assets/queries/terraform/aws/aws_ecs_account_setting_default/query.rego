package kics

import data

__rego_metadata__ := {
  "id": "CUSTOM_AWS_ECS_DEFAULT_LOG_DRIVER_MODE",
  "title": "Ensure defaultLogDriverMode is not set to non-blocking",
  "severity": "MEDIUM",
  "category": "Best Practices",
  "platform": "Terraform"
}

violation[{"message": msg, "resource": resource.address}] {
  resource := input.resource_changes[_]
  resource.type == "aws_ecs_account_setting_default"
  after := resource.change.after
  after.Name == "defaultLogDriverMode"
  after.Value == "non-blocking"
  msg := "defaultLogDriverMode should not be set to non-blocking to avoid potential log loss"
}