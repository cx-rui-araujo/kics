package main

import data.tfconfig

deny[{"resource": sprintf("%s.%s", [resource.type, resource.name]), "message": msg}] {
  resources := tfconfig.resources["aws_cognito_user_pool_client"]
  resource := resources[_]
  instance := resource.instances[_]
  instance.attributes.refresh_token_rotation == false
  msg := "Ensure `refresh_token_rotation` is enabled to prevent reuse of refresh tokens."
}