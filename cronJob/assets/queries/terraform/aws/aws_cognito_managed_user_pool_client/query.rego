package main

__rego_metadata__ := {
  "id": "AWS_COGNITO_001",
  "title": "Ensure Cognito user pool client has refresh token rotation enabled",
  "severity": "HIGH",
  "type": "Security Best Practices",
  "description": "Refresh token rotation should be enabled to prevent reuse of leaked refresh tokens."
}

violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_cognito_user_pool_client"
  after := resource.change.after
  not after.refresh_token_rotation
}