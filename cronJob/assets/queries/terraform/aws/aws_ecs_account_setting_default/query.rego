package main

__rego_metainfo__ := {"id": "KICS-IMAG-001", "title": "Ensure ECS default log driver mode is not non-blocking", "severity": "HIGH", "type": "VULNERABILITY"}

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_ecs_account_setting_default"
  after := resource.change.after
  after.name == "defaultLogDriverMode"
  after.value == "non-blocking"
  msg := "ECS default log driver mode is set to 'non-blocking', which may result in lost logs and hinder auditing."
}
