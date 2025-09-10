package terraform

__rego_metadata__ := {
  "id": "KICS-001",
  "title": "AWS Cognito User Pool Client Refresh Token Rotation Disabled",
  "description": "Ensure that aws_cognito_user_pool_client has refresh_token_rotation enabled to rotate refresh tokens and prevent reuse.",
  "severity": "HIGH",
  "type": "Misconfiguration",
  "platform": "Terraform"
}

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_cognito_user_pool_client"
  after := resource.change.after
  not after.values.refresh_token_rotation
  msg = sprintf("Resource '%s' has refresh_token_rotation disabled", [resource.address])
}