package terraform.security.aws

import data.tfconfig as tfconfig

default allow = false

# Detects aws_cognito_user_pool_client resources without refresh token rotation enabled
violation[resource] {
  resource := tfconfig.resource.aws_cognito_user_pool_client[_]
  # If refresh_token_rotation is missing or not set to true, flag it
  not resource.values.refresh_token_rotation
}