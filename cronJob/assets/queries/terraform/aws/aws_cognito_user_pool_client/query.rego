package aws

__rego_metadata__ := {"id":"AWS_COGNITO_REFRESH_TOKEN_ROTATION","title":"Enable Refresh Token Rotation in Cognito User Pool Client","severity":"HIGH","description":"Ensure that refresh_token_rotation is enabled to prevent refresh token replay attacks."}

deny[msg] {
  input.kind == "terraform"
  resource := input.resource
  resource.type == "aws_cognito_user_pool_client"
  resource.values.refresh_token_rotation == false
  msg := sprintf("Resource '%s' has refresh_token_rotation disabled.", [resource.name])
}