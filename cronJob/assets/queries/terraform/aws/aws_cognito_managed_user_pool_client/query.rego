package main

import data.tfconfig as tfconfig

# Deny if refresh_token_rotation is absent or set to false
deny[msg] {
  resource := tfconfig.resource.aws_cognito_managed_user_pool_client[name]
  not resource.values.refresh_token_rotation
  msg := sprintf("Refresh token rotation is disabled for Cognito User Pool Client '%s', allowing long-lived refresh tokens.", [name])
}