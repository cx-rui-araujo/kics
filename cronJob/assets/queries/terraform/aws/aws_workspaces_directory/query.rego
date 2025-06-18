package kics.aws.WorkSpacesDirectory

# Rule: Weak identity type
violation[issue] {
  resource := input.resource_changes[_]
  resource.type == "aws_workspaces_directory"
  after := resource.change.after
  after.user_identity_type == "SIMPLE_AD"
  issue := {
    "resource": resource.address,
    "message": "WorkSpaces directory 'user_identity_type' is set to SIMPLE_AD which uses a weak built-in directory with default password policies."
  }
}

# Rule: Missing or empty OU DN
violation[issue] {
  resource := input.resource_changes[_]
  resource.type == "aws_workspaces_directory"
  after := resource.change.after
  config := after.active_directory_config
  config.ou_dn == ""
  issue := {
    "resource": resource.address,
    "message": "active_directory_config.ou_dn is empty, leading to default container join which may break group policies."
  }
}

# Rule: Insecure directory name
violation[issue] {
  resource := input.resource_changes[_]
  resource.type == "aws_workspaces_directory"
  after := resource.change.after
  not startswith(after.workspace_directory_name, "corp.")
  issue := {
    "resource": resource.address,
    "message": "WorkSpaces 'workspace_directory_name' does not have the required corporate domain prefix 'corp.'."
  }
}