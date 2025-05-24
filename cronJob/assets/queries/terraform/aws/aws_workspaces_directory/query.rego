package aws.workspaces

__rego_metadata__ := {
  "id": "KICS-NEW-001",
  "title": "Ensure WorkSpaces directory uses SERVICE_DIRECTORY identity type",
  "severity": "HIGH",
  "type": "Misconfiguration",
  "description": "Using an incorrect user_identity_type for aws_workspaces_directory can allow unauthorized access or improper authentication.",
  "recommended_actions": "Set user_identity_type to 'SERVICE_DIRECTORY' for secure AD integration.",
  "reference_id": "aws-workspaces-directory-identity-check"
}

violation[message] {
  resource := tfplan.resource_changes[name]
  resource.type == "aws_workspaces_directory"
  after := resource.change.after
  userType := after.user_identity_type
  userType != "SERVICE_DIRECTORY"
  message := sprintf("aws_workspaces_directory '%s' uses insecure user_identity_type '%s', expected 'SERVICE_DIRECTORY'", [name, userType])
}