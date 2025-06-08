package main

__rego_metadata__ = {
  "id": "KICS-AWS-1234",
  "title": "Ensure refresh token rotation is enabled for Cognito user pool clients",
  "description": "Refresh token rotation should be enabled to prevent token replay attacks.",
  "severity": "HIGH",
  "type": "VULNERABILITY",
  "query": "https://docs.kics.io/latest/creating-queries/"
}

violation[{"msg": msg, "resource": resource.address}] {
  resource := input.resource_changes[_]
  resource.type == "aws_cognito_user_pool_client"
  after := resource.change.after
  (after.refresh_token_rotation == false or not after.refresh_token_rotation)
  msg := sprintf("Resource '%s' has refresh_token_rotation disabled or unset", [resource.address])
}