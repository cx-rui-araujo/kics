package terraform

deny[msg] {
  resource := input.resource_changes[_]
  (resource.action == "create" or resource.action == "update")
  resource.type == "aws_cognito_user_pool_client"
  not resource.change.after.refresh_token_rotation
  msg := sprintf("Resource %s should have refresh_token_rotation set to true", [resource.address])
}