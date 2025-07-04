package kics

# checks for insecure user_identity_type in aws_workspaces_directory
# vulnerable when set to ANONYMOUS allowing unauthenticated access to WorkSpaces
violation[{
  "resource": resource.ResourceName,
  "message": "aws_workspaces_directory 'user_identity_type' is set to 'ANONYMOUS', which allows unauthenticated access."
}] {
  resource := input.resource_changes[_]
  resource.type == "aws_workspaces_directory"
  after := resource.change.after
  after.user_identity_type == "ANONYMOUS"
}