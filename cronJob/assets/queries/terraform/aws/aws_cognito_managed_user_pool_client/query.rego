package main

__rego_metadata__ := {
  "id": "CUSTOM_AWS_001",
  "title": "AWS Cognito User Pool Client should enable refresh_token_rotation",
  "severity": "HIGH",
  "type": "VULNERABILITY",
  "description": "Ensure refresh_token_rotation is enabled to prevent reuse of stolen refresh tokens",
  "recommended_actions": "Set refresh_token_rotation = true on aws_cognito_user_pool_client resources",
  "provider": "aws",
  "resource": "aws_cognito_user_pool_client",
}

violation[{
  "resource": r.Address,
  "message": msg
}] {
  r := input.resources[_]
  r.Type == "aws_cognito_user_pool_client"
  not r.Values.refresh_token_rotation
  msg := sprintf("Resource '%s' has 'refresh_token_rotation' disabled; stolen refresh tokens can be reused", [r.Address])
}