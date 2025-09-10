package aws

violation[res] {
  resource := input.blocks[_]
  resource.type == "resource"
  resource.labels[0] == "aws_cognito_managed_user_pool_client"
  rotation := resource.body.attributes.refresh_token_rotation
  rotation.value == false
  res := {
    "rule_id": "AWS_COGNITO_USER_POOL_CLIENT_REFRESH_TOKEN_ROTATION_DISABLED",
    "message": "Refresh token rotation is disabled for aws_cognito_managed_user_pool_client, allowing reuse of stolen tokens.",
    "severity": "MEDIUM",
    "resource": resource.labels[1]
  }
}