package kics

__rego_metadata__ := {
  "id": "AWS_COGNITO_REFRESH_TOKEN_ROTATION_DISABLED",
  "title": "Cognito User Pool Client Refresh Token Rotation should be enabled",
  "severity": "LOW",
  "type": "Security Best Practice",
  "description": "If refresh token rotation is disabled, tokens may be reused, increasing attack surface."
}

deny[res] {
  resource := input.resource_changes[_]
  resource.type == "aws_cognito_user_pool_client"
  after := resource.change.after
  not after.refresh_token_rotation
  res := {
    "resource": resource.address,
    "message": sprintf("Resource %s has refresh_token_rotation disabled", [resource.address])
  }
}