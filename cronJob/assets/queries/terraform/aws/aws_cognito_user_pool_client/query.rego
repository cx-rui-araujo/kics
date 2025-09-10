package main

metadata = {
  "id": "CKV_AWS_999",
  "title": "Ensure Cognito User Pool Client has refresh token rotation enabled",
  "severity": "MEDIUM",
  "type": "terraform"
}

violation[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_cognito_user_pool_client"
  not resource.change.after.refresh_token_rotation
}