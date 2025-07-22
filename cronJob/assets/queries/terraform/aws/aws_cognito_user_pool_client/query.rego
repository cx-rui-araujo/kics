package main

__rego_metadata__ := {
  "id": "KICS-0001",
  "title": "Cognito User Pool Client must enable refresh token rotation",
  "severity": "HIGH",
  "type": "VIOLATION",
  "description": "Disabling refresh_token_rotation may allow reuse of compromised refresh tokens."
}

deny[msg] {
  resource := input.resource_blocks[_]
  resource.type == "resource"
  resource.labels[0] == "aws_cognito_user_pool_client"
  attr := resource.body.attributes["refresh_token_rotation"]
  attr.value == false
  msg := sprintf("Resource '%s' should have refresh_token_rotation enabled", [resource.labels[1]])
}
