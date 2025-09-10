package terraform.aws.CognitoManagedUserPoolClientRefreshTokenRotation

violation[issue] {
  resource := input.resource_changes[_]
  resource.type == "aws_cognito_managed_user_pool_client"
  after := resource.change.after
  not after.refresh_token_rotation
  issue = {
    "msg": sprintf("Refresh token rotation is not enabled for Cognito Managed User Pool Client '%s'", [resource.address]),
    "resource": resource.address
  }
}
