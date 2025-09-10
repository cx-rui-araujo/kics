package tf_cognito

import data

# Deny if refresh_token_rotation is disabled or not set
deny[msg] {
  client := data.resource_configs.aws_cognito_managed_user_pool_client[_]
  # If attribute is missing or explicitly false, flag it
  not client.attributes.refresh_token_rotation
  msg := sprintf("Cognito user pool client '%s' has refresh_token_rotation disabled or not set", [client.address])
}