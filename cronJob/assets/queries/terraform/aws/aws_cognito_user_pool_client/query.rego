package tfplan

violation[{"resource_id": rc.address, "message": msg}] {
  rc := input.resource_changes[_]
  rc.type == "aws_cognito_user_pool_client"
  rc.change.after.refresh_token_rotation == false
  msg := "Refresh token rotation should be enabled to prevent reuse of refresh tokens"
}