package terraform.aws_cognito_managed_user_pool_client

# Disallow disabling refresh_token_rotation on Cognito User Pool Clients
violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_cognito_managed_user_pool_client"
  # If refresh_token_rotation is missing or explicitly set to false
  not resource.change.after.refresh_token_rotation
}