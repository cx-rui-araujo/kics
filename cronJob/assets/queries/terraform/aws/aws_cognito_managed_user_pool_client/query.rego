package terraform.aws_cognito_managed_user_pool_client

violation[{"msg": msg, "resource": res.address, "rule_id": "AWS_COGNITO_USER_POOL_CLIENT_REFRESH_TOKEN_ROTATION_DISABLED", "severity": "HIGH"}] {
  res := input.resource_changes[_]
  res.type == "aws_cognito_managed_user_pool_client"
  res.change.after.refresh_token_rotation == false
  msg := "Cognito User Pool Client 'refresh_token_rotation' is disabled. Without rotation, refresh tokens can be reused indefinitely if compromised."
}