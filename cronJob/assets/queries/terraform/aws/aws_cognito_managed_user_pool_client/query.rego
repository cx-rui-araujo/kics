package main

__rego_metadata__ := {
  "id": "KICS-0001",
  "version": "1.0.0",
  "title": "Cognito user pool client should have refresh token rotation enabled",
  "description": "Refresh token rotation must be enabled to reduce risk of token replay.",
  "severity": "MEDIUM",
  "category": "Misconfiguration"
}

violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_cognito_managed_user_pool_client"
  not resource.change.after.refresh_token_rotation
}