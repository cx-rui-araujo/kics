package main

# Rule to ensure refresh_token_rotation is enabled for Cognito user pool clients

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_cognito_user_pool_client"
  after := resource.change.after
  # If refresh_token_rotation is not explicitly set to true, flag as violation
  not after.refresh_token_rotation
  msg := sprintf("Resource '%s' has refresh_token_rotation disabled or not set", [resource.address])
}