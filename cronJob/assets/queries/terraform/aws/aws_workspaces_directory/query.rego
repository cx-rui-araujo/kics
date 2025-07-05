package terraform.aws.Workspaces.Directory

violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_workspaces_directory"
  resource.change.after.user_identity_type == "AUTO"
}