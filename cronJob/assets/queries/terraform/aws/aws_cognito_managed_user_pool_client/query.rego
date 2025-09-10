package main

__rego_metadata__ = {
  "id": "AWS123",
  "title": "Ensure Cognito User Pool Client refresh_token_rotation is enabled",
  "severity": "HIGH",
  "type": "VIOLATION",
}

den y[msg] {
  input.resource_changes[_] as rc
  rc.type == "aws_cognito_managed_user_pool_client"
  after := rc.change.after
  not after.refresh_token_rotation
  msg = sprintf("Cognito user pool client %s has refresh_token_rotation disabled or not set, risking reuse of refresh tokens.", [rc.address])
}