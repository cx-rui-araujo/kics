package kics

deny[resource] {
  resource := input.resource
  resource.Type == "aws_workspaces_directory"
  resource.Values.user_identity_type == "IAM"
  resource.Range.Path == ["user_identity_type"]
  resource.Range.Value == "IAM"
}