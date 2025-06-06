package main

violation[{"msg": msg, "resource": resource.address, "severity": "HIGH"}] {
  resource := input.resource_changes[_]
  resource.type == "aws_cognito_user_pool_client"
  after := resource.change.after
  not after.refresh_token_rotation
  msg := sprintf("Resource '%s' has refresh_token_rotation disabled, which can lead to replay attacks", [resource.address])
}
