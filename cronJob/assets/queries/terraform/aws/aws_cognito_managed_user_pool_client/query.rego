package main

deny[response] {
  resource := input.resource[_]
  resource.type == "aws_cognito_managed_user_pool_client"
  # Ensure refresh_token_rotation is explicitly enabled
  not resource.values.refresh_token_rotation

  response := {
    "rule_id": "AWS_COGNITO_REFRESH_TOKEN_ROTATION",
    "resource_id": resource.id,
    "severity": "MEDIUM",
    "message": "Cognito user pool client should have refresh token rotation enabled to prevent refresh token reuse."
  }
}
