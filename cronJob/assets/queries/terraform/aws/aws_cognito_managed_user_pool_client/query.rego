package main

violation[resource] {
  resource := tfconfig.resource.aws_cognito_managed_user_pool_client[_]
  not resource.args.refresh_token_rotation.value
}