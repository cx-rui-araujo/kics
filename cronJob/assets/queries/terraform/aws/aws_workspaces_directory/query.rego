package terraform2

import data.tfconfig

deny[{"msg": msg, "resource": resource_name}] {
  resource := tfconfig.resource_map["aws_workspaces_directory"][resource_name]
  not resource.values.active_directory_config
  msg := "aws_workspaces_directory missing active_directory_config, which may lead to insecure default directory usage."
}