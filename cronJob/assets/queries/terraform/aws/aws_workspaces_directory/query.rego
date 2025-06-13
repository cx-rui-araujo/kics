package terraform.aws

violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_workspaces_directory"
  after := resource.change.after
  after.workspace_type == "AUTOMATIC"
}
