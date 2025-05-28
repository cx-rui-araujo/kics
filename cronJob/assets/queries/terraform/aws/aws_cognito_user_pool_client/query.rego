package main

__rego_metadata__ := {
  "id": "AWS091",
  "title": "Ensure AWS Cognito User Pool Client has refresh token rotation enabled",
  "severity": "MEDIUM",
  "type": "VIOLATION",
  "docs": {
    "recommendation": "Set `refresh_token_rotation = true` in aws_cognito_user_pool_client to mitigate risks from stolen refresh tokens."
  }
}

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_cognito_user_pool_client"
  after := resource.change.after
  # If refresh_token_rotation is explicitly disabled or not defined
  (after.refresh_token_rotation == false) or not after.refresh_token_rotation
  msg := sprintf("aws_cognito_user_pool_client '%s' does not have refresh_token_rotation enabled.", [resource.address])
}