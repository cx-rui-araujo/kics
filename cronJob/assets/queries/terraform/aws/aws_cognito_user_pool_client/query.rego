package main

__rego_metadata__ := {
  "id": "KICS_AWS_100",
  "title": "AWS Cognito User Pool Client with refresh_token_rotation disabled",
  "severity": "MEDIUM",
  "type": "VIOLATION",
}

deny[issue] {
  rc := input.resource_changes[_]
  rc.type == "aws_cognito_user_pool_client"
  after := rc.change.after
  not after.refresh_token_rotation
  issue := {
    "message": sprintf("Resource '%s' has refresh_token_rotation disabled, which can allow reuse of refresh tokens", [rc.address]),
    "resource": rc.address
  }
}