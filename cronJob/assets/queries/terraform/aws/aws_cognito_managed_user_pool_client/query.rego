package main

__rego_meta__ = {
  "id": "AWS.Cognito.UserPoolClient.RefreshTokenRotationDisabled",
  "title": "Ensure Cognito User Pool Client has refresh token rotation enabled",
  "severity": "HIGH"
}

violation[res] {
  resource := input.resource_changes[_]
  resource.type == "aws_cognito_managed_user_pool_client"
  resource.change.after.refresh_token_rotation == false
  res := {
    "resource": resource.address,
    "message": "Cognito user pool client does not have refresh token rotation enabled"
  }
}
