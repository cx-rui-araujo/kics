package main

deny[msg] {
  some name
  resource := input.tfconfig.resource.aws_cognito_user_pool_client[name]
  resource.values.refresh_token_rotation == false
  msg := sprintf("Resource '%s' should have refresh_token_rotation enabled", [name])
}
