package tfawsworkspaces

__rego_metadata__ = {"id":"CUSTOM_AWS_WORKSPACES_UNSAFE_IDENTITY","version":"1.0.0","title":"AWS WorkSpaces Directory with insecure user_identity_type","description":"The `user_identity_type` field should not be set to `SERVICE_PROVIDED` because it may allow unauthorized access.","severity":"HIGH","recommended_action":"Set `user_identity_type` to `AD` for Active Directory authentication."}

deny[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_workspaces_directory"
  after := resource.change.after
  after.user_identity_type == "SERVICE_PROVIDED"
}