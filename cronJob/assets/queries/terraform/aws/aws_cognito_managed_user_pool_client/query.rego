package terraform_plan

# Deny if a Cognito User Pool Client has refresh_token_rotation disabled or unset
deny[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_cognito_managed_user_pool_client"
  # after state may not have the attribute, treat missing as false
  (resource.change.after.refresh_token_rotation == false) 
}
