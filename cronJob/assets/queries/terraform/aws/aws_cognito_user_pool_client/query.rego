package kics

deny[msg] {
  rc := input.resource_changes[_]
  rc.resource_type == "aws_cognito_user_pool_client"
  rc.change.after.refresh_token_rotation == false
  msg := sprintf("Resource '%s' should enable refresh_token_rotation to enhance security.", [rc.address])
}