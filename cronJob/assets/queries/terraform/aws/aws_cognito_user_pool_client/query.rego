package aws_cognito_user_pool_client

deny[resource] {
  resource := input.resources[_]
  resource.Type == "aws_cognito_user_pool_client"
  # Detect when refresh_token_rotation is disabled or not set (defaults to false)
  (not resource.Config.refresh_token_rotation) || resource.Config.refresh_token_rotation == false
}