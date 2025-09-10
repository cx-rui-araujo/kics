package aws.ecs

__rego_metadata__ = {"id":"AWS005","title":"ECS defaultLogDriverMode should not be local","severity":"HIGH","category":"logging"}

violation[{"resource": address, "message": msg}] {
  resource := input.resource_changes[_]
  resource.type == "aws_ecs_account_setting_default"
  address := resource.address
  after := resource.change.after
  after.Name == "defaultLogDriverMode"
  after.Value == "local"
  msg := sprintf("Resource %s uses defaultLogDriverMode 'local', storing logs unencrypted", [address])
}
