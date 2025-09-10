package main

__rego_metadata__ = {
  "id": "KICS_AWS_COGNITO_1",
  "title": "Ensure Cognito User Pool Client has refresh token rotation enabled",
  "severity": "MEDIUM",
  "category": "security"
}

deny[msg] {
  input.resource_type == "aws_cognito_user_pool_client"
  not input.configuration.refresh_token_rotation
  msg := "Refresh token rotation is not enabled for the Cognito User Pool Client."
}