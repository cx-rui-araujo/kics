package main

__rego_metadata__ := {
  "id": "AWS_COGNITO_001",
  "title": "Enable Refresh Token Rotation",
  "description": "Refresh token rotation should be enabled for AWS Cognito Managed User Pool Clients to prevent reuse of stolen refresh tokens.",
  "severity": "MEDIUM"
}

deny[{"resource": name, "message": msg}] {
  resource := tfconfig.resource.aws_cognito_managed_user_pool_client[name]
  resource.values.refresh_token_rotation == false
  msg := sprintf("Refresh token rotation is disabled for Cognito user pool client '%s'", [name])
}