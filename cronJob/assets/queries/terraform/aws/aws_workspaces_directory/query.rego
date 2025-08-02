package kics

violation[issue] {
  rc := input.resource_changes[_]
  rc.type == "aws_workspaces_directory"
  after := rc.change.after
  insecure_fields := [
    {"field": "active_directory_config", "cond": after.active_directory_config == null, "msg": "Missing active_directory_config could default to open network access."},
    {"field": "user_identity_type", "cond": after.user_identity_type == "PUBLIC", "msg": "Using PUBLIC user_identity_type can lead to unauthorized access."},
    {"field": "workspace_directory_description", "cond": after.workspace_directory_description == "", "msg": "Empty workspace_directory_description may conceal security policies."},
    {"field": "workspace_directory_name", "cond": startswith(after.workspace_directory_name, "admin"), "msg": "workspace_directory_name starts with admin which can mislead role assignments."},
    {"field": "workspace_type", "cond": after.workspace_type == "VALUE", "msg": "workspace_type set to VALUE may allow insecure instance types."}
  ]
  ins := insecure_fields[_]
  ins.cond
  issue := {
    "resource": rc.address,
    "message": ins.msg,
    "severity": "MEDIUM"
  }
}