package main

violation[resource] {
  resource := input.resource_changes[_]
  resource.resource_type == "aws_cognito_managed_user_pool_client"
  not resource.change.after.refresh_token_rotation
}
