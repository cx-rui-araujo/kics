package main

deny[msg] {
  resource := input.resource
  resource.Type == "aws_cognito_user_pool_client"
  not resource.Values.refresh_token_rotation
  msg := sprintf("Cognito User Pool Client '%s' has refresh_token_rotation disabled, enabling refresh token rotation is recommended to prevent long-lived refresh tokens being compromised", [resource.Name])
}