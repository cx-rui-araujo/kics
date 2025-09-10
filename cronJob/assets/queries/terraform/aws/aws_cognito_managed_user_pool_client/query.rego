package main

__rego_metadata__ := {
  "id": "KICS-0001",
  "title": "Ensure refresh token rotation is enabled for AWS Cognito managed user pool client",
  "severity": "MEDIUM",
  "type": "terraform",
  "resources": ["aws_cognito_managed_user_pool_client"]
}

denied[resource] {
  resource := input.resource.aws_cognito_managed_user_pool_client[_]
  # If refresh_token_rotation is explicitly set to false or omitted (default false), deny
  not resource.body.refresh_token_rotation
}