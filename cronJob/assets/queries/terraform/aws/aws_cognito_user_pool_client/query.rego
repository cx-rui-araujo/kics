package main

__rego_metadata__ := {
  "id": "KICS_AWS_COGNITO_REFRESH_TOKEN_ROTATION",
  "title": "Ensure refresh token rotation is enabled for Cognito user pool clients",
  "severity": "HIGH",
  "type": "VULNERABILITY"
}

violation[issue] {
  resource := input.resource_changes[_]
  resource.type == "aws_cognito_user_pool_client"
  config := resource.change.after
  not config.refresh_token_rotation
  issue := {
    "resource": resource.address,
    "message": "Refresh token rotation should be enabled to prevent reuse of long-lived refresh tokens"
  }
}