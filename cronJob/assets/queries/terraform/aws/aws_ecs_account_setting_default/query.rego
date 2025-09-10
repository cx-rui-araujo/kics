package kics

__rego_metadata__ = {"id":"KICS-AWS-999","title":"Ensure ECS default log driver mode is not non-blocking","severity":"MEDIUM","type":"MISCONFIGURATION","platform":"Terraform","description":"Non-blocking log driver mode can result in dropped logs."}

fail[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_ecs_account_setting_default"
  resource.change.after.name == "defaultLogDriverMode"
  resource.change.after.value == "non-blocking"
}