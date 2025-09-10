package terraform

violation[resource] {
  resource := tfconfig.resource.aws_workspaces_directory[_]
  adcfg := resource.values.active_directory_config
  adcfg.password_policy.minimum_password_length < 8
}