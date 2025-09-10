package aws.workspaces

violation[resource] {
  resource := input.resource_config.aws_workspaces_directory[_]
  resource.user_identity_type == "ROOT"
}