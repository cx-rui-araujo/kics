package aws_workspaces

__rego_metadata__ = {
  "id": "AWS_WKS_DIRECTORY_ID_SAML_AUTH",
  "title": "Avoid using SAML for user_identity_type in AWS WorkSpaces Directory",
  "severity": "HIGH",
  "type": "misconfiguration",
  "description": "Setting user_identity_type to SAML can expose the directory to unauthorized SSO endpoints if not properly restricted.",
  "recommended_actions": "Use a more restrictive identity type (e.g., SERVICE_PROVIDER) or enforce strict SAML trust policies.",
  "reference": "https://docs.aws.amazon.com/workspaces/latest/adminguide/manage-workspaces-pools-directory.html"
}

deny[message] {
  input.resource_changes[_].type == "aws_workspaces_directory"
  after := input.resource_changes[_].change.after
  after.user_identity_type == "SAML"
  message := sprintf("Resource '%s' uses user_identity_type=SAML which may introduce unauthorized SSO exposure.", [input.resource_changes[_].address])
}