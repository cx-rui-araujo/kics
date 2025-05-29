package main

__rego_metadata__ := {
  "id": "KICS-EXAMPLE-001",
  "title": "Ensure refresh_token_rotation is enabled for Cognito Managed User Pool Clients",
  "severity": "MEDIUM",
  "description": "Refresh token rotation should be enabled to prevent replay attacks when refresh tokens are compromised.",
  "recommended_actions": "Set refresh_token_rotation = true for aws_cognito_managed_user_pool_client resources.",
  "reference_id": ""
}

violation[{
  "msg": msg,
  "resource": resource.address
}] {
  resource := data.terraform.plan.resource_changes[_]
  resource.type == "aws_cognito_managed_user_pool_client"
  after := resource.change.after
  (not after.refresh_token_rotation) or after.refresh_token_rotation == false
  msg := sprintf("Resource '%s' has refresh_token_rotation disabled or not set, which may allow reuse of stolen refresh tokens.", [resource.address])
}