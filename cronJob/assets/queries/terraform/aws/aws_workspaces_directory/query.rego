package main

__rego_metadata__ := {
  "id": "AWS-WORKSPACES-001",
  "title": "Ensure WorkSpaces directory is not configured with PUBLIC workspace_type",
  "severity": "MEDIUM",
  "type": "AWS.WorkSpaces"
}

violation[{
  "message": msg,
  "resource": resource.address
}] {
  resource := input.resource_changes[_]
  resource.type == "aws_workspaces_directory"
  after := resource.change.after
  after.workspace_type == "PUBLIC"
  msg := sprintf("aws_workspaces_directory '%s' uses PUBLIC workspace_type, which may expose directories to unauthorized users.", [resource.address])
}