package main

__rego_meta__ = {
  "id": "AWS_COGNITO_001",
  "title": "Cognito User Pool Client should enable refresh_token_rotation",
  "severity": "HIGH",
  "type": "VIOLATION",
  "category": "Security"
}

deny[msg] {
  input.kind == "resource"
  input.type == "aws_cognito_user_pool_client"
  not input.values.refresh_token_rotation
  msg := sprintf("Resource '%s' should have refresh_token_rotation enabled to ensure refresh tokens are rotated and reduce replay attacks.", [input.name])
}