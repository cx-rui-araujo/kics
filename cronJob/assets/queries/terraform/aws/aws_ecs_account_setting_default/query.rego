package terraform.aws

__rego_metadata__ := {"id": "KICS-AWS-0001", "title": "Non-blocking ECS defaultLogDriverMode may drop logs", "severity": "MEDIUM", "provider": "aws", "service": "ecs"}

deny[msg] {
  input.resource_changes[_] == resource
  resource.type == "aws_ecs_account_setting_default"
  resource.change.after.Name == "defaultLogDriverMode"
  resource.change.after.Value == "non-blocking"
  msg := sprintf("ECS account setting default '%v' uses non-blocking log driver mode which may result in lost logs", [resource.address])
}