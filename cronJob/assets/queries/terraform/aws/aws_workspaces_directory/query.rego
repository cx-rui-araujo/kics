package kics

__rego_metadata__ = {
  "id": "AWS090",
  "title": "Ensure AWS WorkSpaces Directory does not use SERVICE identity without MFA",
  "severity": "MEDIUM",
  "category": "Misconfiguration",
  "description": "Using a SERVICE identity type for an AWS WorkSpaces Directory without enforcing MFA can allow unauthorized access if credentials are compromised.",
  "scope": "resource",
  "affected": {
    "provider": "aws",
    "service": "aws_workspaces_directory",
    "resource": "aws_workspaces_directory"
  }
}

violation[resource] {
  resource := input.resource_changes.aws_workspaces_directory[_]
  after := resource.change.after
  after.user_identity_type == "SERVICE"
  not after.active_directory_config.mfa
}