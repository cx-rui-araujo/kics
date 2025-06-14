package main

__rego_metadata__ := {
  "id": "AWS_COGNITO_REFRESH_TOKEN_ROTATION",
  "version": "1.0.0",
  "title": "Ensure Cognito User Pool Client enables refresh_token_rotation",
  "description": "Disabling refresh token rotation allows stolen refresh tokens to be reused until expiry.",
  "severity": "HIGH",
  "provider": "aws",
  "service": "cognito",
  "resource": "aws_cognito_user_pool_client"
}

deny[msg] {
  resource := terraform.resource_changes["aws_cognito_user_pool_client"][_]
  after := resource.change.after
  not after.refresh_token_rotation
  msg := sprintf("Resource '%s' has refresh_token_rotation disabled or not set", [resource.address])
}