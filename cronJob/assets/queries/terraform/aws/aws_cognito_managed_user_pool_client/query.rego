package terraform

# Rule to detect disabled refresh token rotation in AWS Cognito user pool clients

deny[msg] {
  resource := input.resource.aws_cognito_user_pool_client[_]
  resource.configuration.refresh_token_rotation[0] == false
  msg := sprintf("Resource '%s' has 'refresh_token_rotation' disabled, which increases the risk of token reuse.", [resource.address])
}
