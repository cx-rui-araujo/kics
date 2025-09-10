package tfcognito

import data.tfconfig

violation[resource] {
  resource := tfconfig.resource.aws_cognito_managed_user_pool_client[_]
  not resource.values.refresh_token_rotation
}