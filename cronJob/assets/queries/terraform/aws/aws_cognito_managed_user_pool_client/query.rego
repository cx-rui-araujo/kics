package main

__rego_metadata__ = {
  "id": "KICS_AWS_COGNITO_REFRESH_TOKEN_ROTATION",
  "version": "1.0.0",
  "title": "Ensure refresh token rotation is enabled for Cognito user pool client",
  "description": "Checks that aws_cognito_managed_user_pool_client resources have refresh_token_rotation set to true to prevent reuse of refresh tokens.",
  "severity": "MEDIUM",
  "scope": "resource"
}

violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_cognito_managed_user_pool_client"
  config := resource.change.after
  not config.refresh_token_rotation
}