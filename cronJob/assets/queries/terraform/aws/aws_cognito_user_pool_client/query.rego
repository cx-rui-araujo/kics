package terraform.security.aws

# Deny if refresh_token_rotation is not enabled on a Cognito user pool client
deny[issue] {
  input.kind == "terraform"
  resource := input.resource_changes[_]
  resource.type == "aws_cognito_user_pool_client"
  after := resource.change.after
  not after.refresh_token_rotation
  issue := sprintf(
    "Cognito User Pool Client '%s' has refresh_token_rotation disabled. This may allow reuse of long-lived refresh tokens.",
    [resource.address]
  )
}