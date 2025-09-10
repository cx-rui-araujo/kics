package terraform

# Deny WorkSpaces directories with insecure user_identity_type
# This query catches aws_workspaces_directory resources where user_identity_type is set to ROOT
deny[msg] {
  resource := input.resource_changes.aws_workspaces_directory[_]
  val := resource.change.after.user_identity_type
  val == "ROOT"
  msg := sprintf("WorkSpaces Directory '%s' uses insecure user_identity_type: %s", [resource.change.after.workspace_directory_name, val])
}