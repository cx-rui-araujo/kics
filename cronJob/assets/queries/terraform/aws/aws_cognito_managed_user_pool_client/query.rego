package main

default deny = []

denial[res] {
  resource := input.resource_changes[_]
  resource.type == "aws_cognito_managed_user_pool_client"
  after := resource.change.after
  not after.refresh_token_rotation
  res := {
    "message": sprintf("Refresh token rotation is not enabled for %s", [resource.address]),
    "resource": resource.address
  }
}