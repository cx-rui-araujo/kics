package kics

violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_cognito_managed_user_pool_client"
  resource.change.after.refresh_token_rotation == false
}