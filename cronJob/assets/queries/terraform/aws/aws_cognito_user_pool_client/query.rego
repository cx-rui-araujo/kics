package cognito

violation[{
  "msg": msg,
  "resource": resource_id
}] {
  resource := input.resource_changes[_].after
  resource.type == "aws_cognito_user_pool_client"
  refresh := resource.values.refresh_token_rotation
  refresh == false
  resource_id := resource.address
  msg := sprintf("Resource '%s' has refresh_token_rotation set to false, allowing static refresh tokens that can be reused in replay attacks.", [resource_id])
}