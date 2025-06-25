package kics

# Deny when aws_workspaces_directory uses a non-auto-stop workspace_type, which may lead to unnecessary exposure and higher costs
deny[msg] {
  resource := input.resources.aws_workspaces_directory[_]
  workspace_type := resource.values.workspace_type
  workspace_type == "STANDARD"
  addr := resource.address
  msg = sprintf("Resource '%s' uses insecure workspace_type '%s'. Use 'AUTO_STOP' to reduce exposure and costs.", [addr, workspace_type])
}