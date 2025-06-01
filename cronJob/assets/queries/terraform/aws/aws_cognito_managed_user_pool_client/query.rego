package main

__rego_metadata__ = {"id":"AWS_COGNITO_001","version":"1.0.0","title":"Ensure refresh_token_rotation is enabled on Cognito user pool clients","severity":"MEDIUM","description":"Cognito user pool clients should enable refresh token rotation to prevent reuse of tokens."}

violation[resource] {
  resource := input.resource.aws_cognito_managed_user_pool_client[_]
  not resource.refresh_token_rotation
}