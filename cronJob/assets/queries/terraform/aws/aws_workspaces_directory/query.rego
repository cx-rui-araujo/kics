package kics

default deny = false

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_workspaces_directory"
  after := resource.change.after
  # Imaginary vulnerability: plain-text AD password in active_directory_config
  pwd := after.active_directory_config.password
  pwd != ""
  msg = sprintf("Hardcoded AD password detected in aws_workspaces_directory '%s'", [after.directory_id])
}