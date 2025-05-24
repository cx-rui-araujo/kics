package kics

__rego_metadata__ = {
  "id": "AWS_COGNITO_USER_POOL_CLIENT_REFRESH_ROTATION",
  "title": "Cognito user pool client should enable refresh token rotation",
  "severity": "HIGH",
  "type": "VULNERABILITY"
}

denied[msg] {
  input.resource_changes[_] == change
  change.type == "aws_cognito_user_pool_client"
  after := change.change.after
  not after.refresh_token_rotation
  msg := sprintf("aws_cognito_user_pool_client '%v' has refresh_token_rotation disabled or not set, which may allow reuse of stolen refresh tokens.", [after.name])
}