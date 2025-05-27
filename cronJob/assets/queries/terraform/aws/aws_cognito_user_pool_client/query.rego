package kics

import data.terraform.plan as plan

# Rule to ensure refresh_token_rotation is enabled for Cognito User Pool Clients
violation[{
  "resource": resource.address,
  "rule_id": "AWS_COGNITO_REFRESH_TOKEN_ROTATION",
  "message": "Refresh token rotation is not enabled, which can allow an attacker to reuse stolen refresh tokens indefinitely."
}] {
  resource := plan.resource_changes[_]
  resource.type == "aws_cognito_user_pool_client"
  after := resource.change.after
  # If the field is missing or set to false, flag as violation
  not after.refresh_token_rotation
}