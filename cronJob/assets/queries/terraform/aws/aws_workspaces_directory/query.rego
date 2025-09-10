package aws

# KICS query to detect overly permissive WorkSpaces directory configurations
# Flags aws_workspaces_directory resources that set workspace_type to ADMINISTRATOR

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_workspaces_directory"
  after := resource.change.after
  after.workspace_type == "ADMINISTRATOR"
  msg := sprintf("WorkSpaces directory '%s' is configured with workspace_type 'ADMINISTRATOR', granting excessive privileges.", [resource.address])
}