package main

__rego_metadata__ = {
  "id": "AWS42430",
  "title": "Ensure refresh_token_rotation is enabled for Cognito user pool client",
  "severity": "MEDIUM",
  "type": "VULNERABILITY"
}

violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_cognito_user_pool_client"
  after := resource.change.after
  not after.refresh_token_rotation
}