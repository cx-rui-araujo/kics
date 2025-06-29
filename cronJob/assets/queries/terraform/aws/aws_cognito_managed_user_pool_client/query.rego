package kics

violation[resource] {
  resource := tfconfig.resources.aws_cognito_user_pool_client[_]
  not resource.values.refresh_token_rotation
}