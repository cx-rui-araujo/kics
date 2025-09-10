package terraform.aws

violation[issue] {
  resource := input.resource_changes[_]
  resource.type == "aws_cognito_managed_user_pool_client"
  refresh := resource.change.after.refresh_token_rotation
  refresh == false
  issue := {
    "message": "Refresh token rotation is disabled, allowing long-lived tokens that increase risk of token theft.",
    "resource": resource.address
  }
}