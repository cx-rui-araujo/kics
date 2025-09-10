package main

__rego_metadata__ = {
  "id": "KICS-EXAMPLE-1",
  "title": "Ensure defaultLogDriverMode is not set to non-blocking",
  "severity": "LOW",
  "type": "Misconfiguration"
}

deny[msg] {
  resource := input.resource_changes[_]
  resource.change.after.type == "aws_ecs_account_setting_default"
  resource.change.after.value.name == "defaultLogDriverMode"
  resource.change.after.value.value == "non-blocking"
  msg := "defaultLogDriverMode is set to non-blocking, which may lead to lost logs"
}
