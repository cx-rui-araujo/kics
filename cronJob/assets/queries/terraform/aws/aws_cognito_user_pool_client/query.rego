package aws

__rego_metadoc__ = {
  "id": "AWS.CognitoUserPoolClient.RefreshTokenRotationDisabled",
  "title": "Refresh token rotation should be enabled for Cognito User Pool Client",
  "description": "Disabling refresh token rotation increases the risk of refresh token reuse attacks.",
  "severity": "MEDIUM",
  "link": "https://docs.aws.amazon.com/cognito/latest/developerguide/refresh-token-rotation.html"
}

denied[resource] {
  resource := input.resource_changes[_]
  resource.type == "aws_cognito_user_pool_client"
  after := resource.change.after
  (
    after.refresh_token_rotation == false
    or not after.refresh_token_rotation
  )
}