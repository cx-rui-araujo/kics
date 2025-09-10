package terraform.cognito

violation[{"resource_name": addr, "message": msg}] {
  rc := input.resource_changes[_]
  rc.type == "aws_cognito_managed_user_pool_client"
  after := rc.change.after
  not after.refresh_token_rotation
  addr := rc.address
  msg := "Refresh token rotation should be enabled for aws_cognito_managed_user_pool_client to prevent token replay attacks."
}