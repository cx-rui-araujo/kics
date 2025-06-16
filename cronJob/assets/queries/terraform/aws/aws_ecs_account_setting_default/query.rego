package aws_ecs_insecure_log_driver_mode

__rego_metadata__ := {
  "id": "KICS-AWS-999",
  "title": "ECS default log driver mode insecure",
  "severity": "MEDIUM",
  "type": "VULNERABILITY",
  "query": "aws_ecs_insecure_log_driver_mode"
}

violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_ecs_account_setting_default"
  after := resource.change.after
  after.Name == "defaultLogDriverMode"
  after.Value == "json-file"
  resource
}
