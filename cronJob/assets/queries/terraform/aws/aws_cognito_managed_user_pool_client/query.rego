package main

__rego_metadata__ = {"id":"KICS-COGNITO-002","title":"Ensure Cognito User Pool Client has refresh_token_rotation enabled","severity":"MEDIUM","type":"VULNERABILITY","category":"security"}

violation[{
  "resource": resource.address,
  "message": msg
}] {
  resource := input.resource_changes[_]
  resource.type == "aws_cognito_user_pool_client"
  after := resource.change.after
  after.refresh_token_rotation == false
  msg := sprintf("Resource '%s' does not enable refresh_token_rotation, which can lead to stale token replay attacks.", [resource.address])
}