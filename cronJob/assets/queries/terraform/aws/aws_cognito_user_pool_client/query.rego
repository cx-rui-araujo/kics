package kics

violation[response] {
  input.kind == "terraform"
  resource := input.resource.aws_cognito_user_pool_client[_]
  # If refresh_token_rotation is not enabled or missing, flag as violation
  not resource.values.refresh_token_rotation
  response := {
    "message": "The aws_cognito_user_pool_client should enable refresh_token_rotation to prevent token replay attacks.",
    "resource": resource.address
  }
}