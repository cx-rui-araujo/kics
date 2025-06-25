package main

# Deny if refresh_token_rotation is not enabled on Cognito user pool clients to prevent refresh token reuse

deny[msg] {
  # iterate over all aws_cognito_user_pool_client resources
  resourceList := input.resource.aws_cognito_user_pool_client[_]
  # get the first instance of the resource block
  resource := resourceList[0]
  # check if refresh_token_rotation is missing or explicitly false
  resource.refresh_token_rotation != true
  msg := "aws_cognito_user_pool_client has refresh_token_rotation disabled or not set. This can lead to refresh token reuse and replay attacks."
}