package kics

violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_cognito_user_pool_client"
  after := resource.change.after
  after.refresh_token_rotation == false
}