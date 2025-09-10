package main

__rego__ := {
  "id": "KICS_AWS_COGNITO_REFRESH_TOKEN_ROTATION",
  "title": "Enable refresh_token_rotation in aws_cognito_managed_user_pool_client",
  "description": "Refresh token rotation ensures refresh tokens can only be reused once and reduces the risk of token replay attacks.",
  "severity": "MEDIUM",
  "type": "VIOLATION",
  "metadata": {
    "references": ["https://docs.aws.amazon.com/cognito/latest/developerguide/token-revocation.html"]
  }
}

denied[issue] {
  input.resource_changes[_] == resource
  resource.type == "aws_cognito_managed_user_pool_client"
  after := resource.change.after
  not after.refresh_token_rotation
  issue := {
    "message": sprintf("aws_cognito_managed_user_pool_client '%s' has refresh_token_rotation disabled or not set", [resource.address]),
    "resource": resource.address
  }
}