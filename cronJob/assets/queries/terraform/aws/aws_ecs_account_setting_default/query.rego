package terraform.aws.ecs.account_setting_default

__rego_metadata__ = {
  "id": "AWS_ECS_0001",
  "title": "Ensure defaultLogDriverMode is not set to non-blocking",
  "severity": "LOW",
  "category": "Misconfiguration"
}

deny[msg] {
  input.resource_changes[_] = rc
  rc.type == "aws_ecs_account_setting_default"
  rc.change.after.Name == "defaultLogDriverMode"
  rc.change.after.value == "non-blocking"
  msg = "Setting defaultLogDriverMode to non-blocking can cause dropped logs and loss of critical audit information. Use 'default' mode instead."
}