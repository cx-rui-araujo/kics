package terraform.aws.Workspaces

violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_workspaces_directory"
  after := resource.change.after
  cfg := after.active_directory_config
  password := cfg[0].password
  password != ""
}