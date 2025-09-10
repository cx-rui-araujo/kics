package main

__rego_metadata__ = {
  "id": "KICS_AWS_COGNITO_001",
  "title": "Ensure refresh_token_rotation is enabled for Cognito User Pool Client",
  "severity": "HIGH",
  "type": "Misconfiguration",
}

violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_cognito_user_pool_client"
  after := resource.change.after
  after.refresh_token_rotation == false
}