package main

import data.tfconfig

deny[info] {
  tfconfig.resource.aws_cognito_user_pool_client[res_id] == resource
  resource.refresh_token_rotation != true
  info := {
    "msg": "aws_cognito_user_pool_client 'refresh_token_rotation' is not enabled, which may allow reuse of refresh tokens.",
    "resource": res_id
  }
}
