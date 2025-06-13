package terraform.aws

__rego_metadata__
{
  "id": "AWS-LOG-001",
  "title": "Non-blocking defaultLogDriverMode can drop logs",
  "severity": "HIGH",
  "type": "VIOLATION"
}
__end_rego_metadata__

deny[{
  "msg": msg,
  "resource": resource.address
}] {
  resource := input.resource_changes[_]
  resource.type == "aws_ecs_account_setting_default"
  after := resource.change.after
  after.Name == "defaultLogDriverMode"
  after.Value != "blocking"
  msg := sprintf("Resource %s has defaultLogDriverMode set to %s which may drop logs", [resource.address, after.Value])
}