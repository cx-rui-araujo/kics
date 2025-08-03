package main

import data.tfconfig as tfconfig

# Deny Cognito managed user pool clients without refresh token rotation enabled
deny[violation] {
  resource := tfconfig.resource[_]
  resource.type == "aws_cognito_managed_user_pool_client"
  # If refresh_token_rotation is missing or explicitly set to false
  (not resource.attributes.refresh_token_rotation) || (resource.attributes.refresh_token_rotation.value == false)
  violation := {
    "msg": sprintf("Refresh token rotation should be enabled for Cognito managed user pool client '%s'", [resource.name]),
    "resource": resource
  }
}