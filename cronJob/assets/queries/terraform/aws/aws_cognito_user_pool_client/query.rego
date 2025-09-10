package main

__rego_metadata__ := {
  "id": "AWSCognitoUserPoolClientRefreshTokenRotationDisabled",
  "title": "AWS Cognito User Pool Client has refresh_token_rotation disabled",
  "severity": "MEDIUM",
  "type": "Misconfiguration",
  "impact": "Refresh tokens never expire and remain valid indefinitely.",
  "resolution": "Enable refresh_token_rotation to rotate refresh tokens on use.",
  "reference_id": "AWS.COGNITO.103",
  "cwe": "613",
  "documentation": {
    "summary": "Disabling refresh token rotation can lead to perpetual valid tokens and security risk if a token is compromised.",
    "links": ["https://docs.aws.amazon.com/cognito/latest/developerguide/token-endpoint.html"]
  }
}

violation[resource] {
  resource := input.resource[_]
  resource.type == "aws_cognito_user_pool_client"
  resource.values.refresh_token_rotation == false
}