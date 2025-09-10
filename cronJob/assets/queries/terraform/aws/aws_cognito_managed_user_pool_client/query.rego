package main

__rego_metadata__ := {
  "id": "KICS-AWS-COGNITO-REFRESH-TOKEN-ROTATION-001",
  "version": "1.0.0",
  "title": "Ensure refresh_token_rotation is enabled for Cognito Managed User Pool Client",
  "severity": "MEDIUM",
  "description": "Disablement or absence of refresh token rotation can allow reuse of stolen refresh tokens.",
  "recommendation": "Set `refresh_token_rotation = true` in aws_cognito_managed_user_pool_client resources.",
  "tags": ["aws","cognito","security"]
}

denied_resources[message] {
  resource := input.blocks[_]
  resource.type == "resource"
  resource.labels[0] == "aws_cognito_managed_user_pool_client"

  # If the attribute is missing or explicitly false
  attr := resource.attributes.refresh_token_rotation
  (not attr) or (attr.value == false)

  message := sprintf("Resource '%s' must enable refresh_token_rotation to true.", [resource.labels[1]])
}