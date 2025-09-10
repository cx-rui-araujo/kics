package main

__rego_metadata__ = {
  "id": "AWS.Cognito.UserPoolClient.RefreshTokenRotation",
  "title": "Ensure refresh token rotation is enabled for Cognito User Pool Client",
  "severity": "MEDIUM",
  "type": "VIOLATION",
  "description": "Cognito User Pool Clients should have refresh_token_rotation enabled to prevent reuse of stolen refresh tokens."
}

denied[msg] {
  resource := input.resource.aws_cognito_user_pool_client[_]
  not resource.refresh_token_rotation
  msg := sprintf("Cognito User Pool Client '%s' does not have refresh_token_rotation enabled", [resource.name])
}