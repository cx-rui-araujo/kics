package main

__rego_metadata__ := {
  "id": "KICS-9999",
  "title": "Cognito User Pool Client refresh_token_rotation disabled",
  "severity": "MEDIUM",
  "type": "terraform",
  "queryName": "cognito-user-pool-client-refresh-token-rotation"
}

violation[resource] {
  resource := input.Blocks[_]
  resource.Type == "resource"
  resource.Labels[0] == "aws_cognito_user_pool_client"
  attr := resource.Body.Attributes["refresh_token_rotation"]
  attr != null
  attr.Value == "false"
}