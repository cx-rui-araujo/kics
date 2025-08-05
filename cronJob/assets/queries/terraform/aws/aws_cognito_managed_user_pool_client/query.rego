package kics

violation[{"msg": msg, "resource": resource}] {
  resource := input.resource_changes[_]
  resource.type == "aws_cognito_managed_user_pool_client"
  not resource.change.after.refresh_token_rotation
  msg := "aws_cognito_managed_user_pool_client should enable refresh_token_rotation to prevent reuse of stolen tokens"
}