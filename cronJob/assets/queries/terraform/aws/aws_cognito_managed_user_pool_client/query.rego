package aws

violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_cognito_managed_user_pool_client"
  resource.change.after.refresh_token_rotation == false
  message := sprintf("Resource '%s' has refresh_token_rotation disabled, risking long-lived tokens.", [resource.address])
}