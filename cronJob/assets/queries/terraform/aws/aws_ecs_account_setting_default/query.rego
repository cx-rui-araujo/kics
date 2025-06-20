package aws.ecs

__rego_metadata__ := {
  "id": "KICS-AWS-DEFAULT-LOG-DRIVER-MODE-INSECURE",
  "title": "Ensure ECS defaultLogDriverMode is set to a secure driver",
  "description": "Using an unstructured or non-json log driver mode can lead to loss of structured logs or exposure of sensitive data.",
  "severity": "MEDIUM",
  "recommended_actions": "Set defaultLogDriverMode to 'json-file' or another structured log driver."
}

deny[msg] {
  resource := input.resource.aws_ecs_account_setting_default[_]
  name := resource.setting_name
  name.value == "defaultLogDriverMode"
  val := resource.setting_value.value
  val != "json-file"
  msg := sprintf("Resource '%s' uses insecure defaultLogDriverMode '%s'.", [resource.address, val])
}