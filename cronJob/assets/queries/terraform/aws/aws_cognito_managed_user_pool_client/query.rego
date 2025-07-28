package main

import data.terraform.tfplan as tfplan

violation[res] {
  resource := tfplan.resource_changes[_]
  resource.type == "aws_cognito_user_pool_client"
  action := resource.change.actions[_]
  action == "create" || action == "update"
  not resource.change.after.refresh_token_rotation
  res := {
    "Message": "Cognito user pool client does not have refresh token rotation enabled",
    "ResourceName": resource.address
  }
}