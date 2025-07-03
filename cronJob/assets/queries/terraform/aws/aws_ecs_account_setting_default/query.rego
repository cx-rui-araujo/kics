package kics

__rego_metadata__ := {
  "id": "KICS-DEFAULT-LOG-MODE",
  "title": "Ensure ECS defaultLogDriverMode is not set to 'none'",
  "severity": "HIGH",
  "type": "terraform",
  "metadata": {}
}

violation[{"msg": msg}] {
  resource := input.resource_changes[_]
  resource.type == "aws_ecs_account_setting_default"
  resource.change.after.Name == "defaultLogDriverMode"
  resource.change.after.Value == "none"
  msg := "ECS defaultLogDriverMode is set to 'none', logs will not be captured and this may violate compliance requirements."
}