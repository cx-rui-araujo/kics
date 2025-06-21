package k8srules

# Ensure AWS Cognito User Pool Client has refresh_token_rotation enabled
violation[resource] {
  resource := input.resource_instances[_]
  resource.type == "aws_cognito_user_pool_client"
  # If refresh_token_rotation is missing or explicitly set to false
  not resource.values.refresh_token_rotation
}