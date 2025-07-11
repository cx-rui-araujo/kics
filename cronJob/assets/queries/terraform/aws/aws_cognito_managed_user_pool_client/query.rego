package main

__rego_metadata__ = {
  "id": "AWS_COGNITO_001",
  "title": "Cognito User Pool Client without refresh token rotation",
  "severity": "HIGH",
  "type": "VULNERABILITY",
}

violation[resource] {
  resource := terraform.resources.aws_cognito_user_pool_client[_]
  # If refresh_token_rotation is not set or explicitly false
  not resource.values.refresh_token_rotation
}