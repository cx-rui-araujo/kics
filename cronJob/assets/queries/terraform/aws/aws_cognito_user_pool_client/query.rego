package terraform.aws.cognito

__rego_metadata__ := {
  "id": "AWS_COGNITO_REFRESH_TOKEN_ROTATION_DISABLED",
  "title": "Cognito User Pool Client Refresh Token Rotation Disabled",
  "severity": "HIGH",
  "type": "VULNERABILITY",
  "impact": "Stolen refresh tokens can be reused indefinitely if rotation is disabled.",
  "resolution": "Enable `refresh_token_rotation` for aws_cognito_user_pool_client to ensure refresh tokens are rotated.",
  "reference_id": "AWS.COGNITO.REFRESH_TOKEN_ROTATION"
}

denied[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_cognito_user_pool_client"
  after := resource.change.after
  after.refresh_token_rotation == false
  msg := sprintf("Resource '%s' has refresh_token_rotation disabled, exposing it to token replay attacks.", [resource.address])
}