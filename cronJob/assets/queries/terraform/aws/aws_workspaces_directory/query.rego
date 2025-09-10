package kics

violation[{"message": msg, "resource": resource}] {
  resource := input.resource_changes[_]
  resource.type == "aws_workspaces_directory"
  after := resource.change.after
  # Imaginary vulnerability: missing active_directory_config leads to insecure WorkSpaces directory setup
  not after.active_directory_config
  msg := "aws_workspaces_directory 'active_directory_config' is not set, which may expose WorkSpaces to directory misconfiguration vulnerabilities."
}