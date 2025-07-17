package main

__rego_meta__ := {
  "id": "AWS_COGNITO_REFRESH_TOKEN_ROTATION",
  "title": "Ensure Cognito User Pool Client has refresh token rotation enabled",
  "severity": "MEDIUM",
  "type": "VIOLATION"
}

violation[issue] {
  input.resource_changes[_] as rc
  rc.type == "aws_cognito_managed_user_pool_client"
  after := rc.change.after
  not after.refresh_token_rotation
  issue := {
    "resource": rc.address,
    "message": "Refresh token rotation is disabled; this may allow reuse of compromised refresh tokens."
  }
}