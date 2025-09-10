package terraform.aws.WorkSpaces

__rego_metadata__ = {
    "id": "KICS-9001",
    "title": "AWS WorkSpaces Directory Active Directory Config must enable encryption",
    "severity": "HIGH",
    "category": "encryption",
    "description": "Detect aws_workspaces_directory resources where active_directory_config.encryption_enabled is not set to true, which may expose sensitive directory credentials.
}

denied[issue] {
  resource := input.resource_changes.aws_workspaces_directory[_]
  after := resource.change.after
  active_cfg := after.active_directory_config
  active_cfg != null
  not active_cfg.encryption_enabled
  issue := {
    "msg": sprintf("aws_workspaces_directory '%s' defines active_directory_config without encryption_enabled set to true", [resource.address]),
    "resource": resource.address
  }
}