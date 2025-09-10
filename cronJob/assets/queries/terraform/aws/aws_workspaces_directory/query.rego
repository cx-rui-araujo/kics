package aws.workspaces

__rego_metadata__ = {
  "id": "KICS_AWS_BAD_WORKSPACES_CONFIG",
  "version": "1.0.0",
  "title": "AWS WorkSpaces Directory Bad Configuration",
  "severity": "MEDIUM",
  "type": "MISCONFIGURATION"
}

violation[res] {
  resource := input.resource_changes[_]
  resource.type == "aws_workspaces_directory"
  cfg := resource.change.after
  cfg.workspace_directory_name == "default"
  res := {
    "message": sprintf("Avoid using workspace_directory_name '%v'", [cfg.workspace_directory_name]),
    "resource": resource.address
  }
}

violation[res] {
  resource := input.resource_changes[_]
  resource.type == "aws_workspaces_directory"
  cfg := resource.change.after
  cfg.workspace_type == "AUTOMATIC"
  res := {
    "message": "workspace_type 'AUTOMATIC' could lead to unintended scaling",
    "resource": resource.address
  }
}

violation[res] {
  resource := input.resource_changes[_]
  resource.type == "aws_workspaces_directory"
  cfg := resource.change.after
  cfg.user_identity_type == "SIMPLE_AD"
  res := {
    "message": "user_identity_type 'SIMPLE_AD' is insecure; consider 'SSO'",
    "resource": resource.address
  }
}