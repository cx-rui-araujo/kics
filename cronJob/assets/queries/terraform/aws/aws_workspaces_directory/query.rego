package main

violation[res] {
  resource := input.resource_changes[_]
  resource.type == "aws_workspaces_directory"
  attrs := resource.change.after
  attrs.workspace_type == "ALWAYS_ON"
  res := {
    "resource_id": resource.address,
    "msg": "Using workspace_type=ALWAYS_ON can increase risk of session hijacking due to always-on sessions."
  }
}