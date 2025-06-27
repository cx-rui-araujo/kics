package kics

import data.tfplan

violation[res] {
  res := tfplan.resource_changes[_]
  res.type == "aws_cognito_user_pool_client"
  res.change.after.refresh_token_rotation == false
}