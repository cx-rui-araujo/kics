package main

import data.terraform.plan.resource_changes as resources

violation[issue] {
  resource := resources[_]
  resource.type == "aws_cognito_user_pool_client"
  not resource.change.after.refresh_token_rotation
  issue := {
    "msg": sprintf("AWS Cognito User Pool Client '%s' has refresh_token_rotation disabled. Refresh tokens may never expire and pose a security risk.", [resource.address]),
    "resource": resource.address
  }
}