package aws_cognito_user_pool_client

import data.terraform_plan as tfplan

violation[resource] {
  resource := tfplan.resource_changes[_]
  resource.type == "aws_cognito_user_pool_client"
  resource.change.after.refresh_token_rotation == false
}