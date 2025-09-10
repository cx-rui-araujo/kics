package tfsec.aws

# Ensure refresh token rotation is enabled for Cognito user pool client
deny[msg] {
  rc := input.resource_changes[_]
  rc.type == "aws_cognito_user_pool_client"
  # Check that refresh_token_rotation is explicitly enabled
  not rc.change.after.refresh_token_rotation
  msg := sprintf("Refresh token rotation is disabled for Cognito user pool client %s", [rc.address])
}