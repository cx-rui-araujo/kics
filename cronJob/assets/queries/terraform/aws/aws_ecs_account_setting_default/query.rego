package terraform

deny[msg] {
  resource := resource_instances[i]
  resource.Type == "aws_ecs_account_setting_default"
  resource.Values.Name == "defaultLogDriverMode"
  resource.Values.Value == "non-blocking"
  msg = sprintf("Resource %s uses non-blocking defaultLogDriverMode (may drop logs)", [resource.Address])
}