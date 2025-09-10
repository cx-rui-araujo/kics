package main

violation[{
  "msg": "Refresh token rotation is disabled, making tokens long-lived and vulnerable to replay attacks.",
  "resource": resource.address
}] {
  resource := input.resource_changes[_]
  resource.type == "aws_cognito_user_pool_client"
  after := resource.change.after
  (not after.refresh_token_rotation) or after.refresh_token_rotation == false
}