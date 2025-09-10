package aws.workspaces

__rego_metadata__ := {
  "id": "AWS_WKS_001",
  "title": "Ensure AWS WorkSpaces Directory user_identity_type is SERVICE_PROVIDER",
  "severity": "HIGH",
  "type": "VIOLATION"
}

denied[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_workspaces_directory"
  after := resource.change.after
  user_identity := after.user_identity_type
  user_identity != "SERVICE_PROVIDER"
  msg = sprintf("aws_workspaces_directory '%s' has insecure user_identity_type '%s', must be SERVICE_PROVIDER", [after.workspace_directory_name, user_identity])
}