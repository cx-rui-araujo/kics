package kics

violation[{"msg": msg, "resource": res.address}] {
  res := input.resource_changes[_]
  res.type == "aws_cognito_managed_user_pool_client"
  res.change.after.refresh_token_rotation == false
  msg := sprintf("Resource '%s' has refresh_token_rotation disabled, allowing stolen tokens to be reused indefinitely.", [res.address])
}