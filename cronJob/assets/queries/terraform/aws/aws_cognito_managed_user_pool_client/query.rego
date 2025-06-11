package main

deny[msg] {
  resource := input.resource.aws_cognito_user_pool_client[_]
  (
    resource.refresh_token_rotation == false
    or not resource.refresh_token_rotation
  )
  msg = sprintf("Cognito User Pool Client '%s' has refresh_token_rotation disabled or not set, which can allow long-lived token reuse.", [resource.name])
}