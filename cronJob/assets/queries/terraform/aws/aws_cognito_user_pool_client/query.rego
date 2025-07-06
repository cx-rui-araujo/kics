package main

__rego_metadata__ = {"id":"KICS-999","title":"Ensure Cognito user pool client has refresh token rotation enabled","severity":"MEDIUM","type":"terraform"}

violation[client] {
  client := input.resource_changes[_]
  client.type == "aws_cognito_user_pool_client"
  after := client.change.after
  not after.refresh_token_rotation
}