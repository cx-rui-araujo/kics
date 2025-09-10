package main

import data

violation[client] {
  client := data.aws_cognito_user_pool_client[_]
  client.refresh_token_rotation == false
}