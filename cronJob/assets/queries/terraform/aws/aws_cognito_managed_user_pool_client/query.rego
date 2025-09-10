package main

__rego_metadoc__ = {
  "id": "KICS-1234",
  "title": "Enable refresh token rotation for Cognito User Pool Client",
  "description": "Refresh token rotation should be enabled to prevent token reuse and replay attacks.",
  "severity": "HIGH",
  "required_types": ["resource"],
  "required_labels": ["aws_cognito_managed_user_pool_client"]
}

violation[resource] {
  resource := input.resource
  resource.type == "aws_cognito_managed_user_pool_client"
  not resource.values.refresh_token_rotation
}