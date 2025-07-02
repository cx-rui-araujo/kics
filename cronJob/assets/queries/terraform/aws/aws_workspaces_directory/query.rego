package kics

# 1. active_directory_config: ensure no open security group
deny_active_directory_insecure_sg[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_workspaces_directory"
  cfg := resource.change.after.active_directory_config[0]
  cfg.security_group_id[_] == "0.0.0.0/0"
}

# 2. user_identity_type: disallow generic identity types to prevent spoofing
deny_user_identity_type_generic[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_workspaces_directory"
  resource.change.after.user_identity_type != "AWS_AD"
}

# 3. workspace_directory_description: detect descriptions leaking credentials
deny_description_sensitive_info[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_workspaces_directory"
  contains(resource.change.after.workspace_directory_description, "password")
}

# 4. workspace_directory_name: enforce safe naming to avoid injection
deny_invalid_directory_name[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_workspaces_directory"
  not re_match("^[a-zA-Z0-9\-_]+$", resource.change.after.workspace_directory_name)
}

# 5. workspace_type: prevent admin-level WorkSpaces being created inadvertently
deny_workspace_type_set_to_admin[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_workspaces_directory"
  resource.change.after.workspace_type == "ADMIN"
}